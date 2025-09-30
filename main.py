from fastapi import FastAPI, HTTPException, Depends, status, File, UploadFile
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from typing import List, Optional
import sqlite3
import hashlib
import jwt
from datetime import datetime, timedelta
import os
import uuid
import shutil
from pathlib import Path

# Configuration
SECRET_KEY = "your-secret-key-change-this-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
TELEGRAM_CHANNEL = "@amoragifts"  # Change this to your actual channel

# Create directories
os.makedirs("uploads", exist_ok=True)
os.makedirs("static", exist_ok=True)

# FastAPI app
app = FastAPI(title="Gift Shop API", description="Backend API for Gift Shop Website")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files
app.mount("/static", StaticFiles(directory="uploads"), name="static")

# Security
security = HTTPBearer()


# Database initialization
def init_db():
    conn = sqlite3.connect('giftshop.db')
    cursor = conn.cursor()

    # Products table
    cursor.execute('''
                   CREATE TABLE IF NOT EXISTS products
                   (
                       id
                       INTEGER
                       PRIMARY
                       KEY
                       AUTOINCREMENT,
                       name
                       TEXT
                       NOT
                       NULL,
                       description
                       TEXT,
                       price
                       DECIMAL
                   (
                       10,
                       2
                   ) NOT NULL,
                       category TEXT,
                       image_url TEXT,
                       stock_quantity INTEGER DEFAULT 0,
                       is_active BOOLEAN DEFAULT 1,
                       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                       updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                       )
                   ''')

    # Admin users table
    cursor.execute('''
                   CREATE TABLE IF NOT EXISTS admin_users
                   (
                       id
                       INTEGER
                       PRIMARY
                       KEY
                       AUTOINCREMENT,
                       username
                       TEXT
                       UNIQUE
                       NOT
                       NULL,
                       password_hash
                       TEXT
                       NOT
                       NULL,
                       email
                       TEXT,
                       created_at
                       TIMESTAMP
                       DEFAULT
                       CURRENT_TIMESTAMP
                   )
                   ''')

    # Categories table
    cursor.execute('''
                   CREATE TABLE IF NOT EXISTS categories
                   (
                       id
                       INTEGER
                       PRIMARY
                       KEY
                       AUTOINCREMENT,
                       name
                       TEXT
                       UNIQUE
                       NOT
                       NULL,
                       description
                       TEXT,
                       created_at
                       TIMESTAMP
                       DEFAULT
                       CURRENT_TIMESTAMP
                   )
                   ''')

    # Orders table (for tracking telegram orders)
    cursor.execute('''
                   CREATE TABLE IF NOT EXISTS orders
                   (
                       id
                       INTEGER
                       PRIMARY
                       KEY
                       AUTOINCREMENT,
                       customer_name
                       TEXT,
                       customer_contact
                       TEXT,
                       product_id
                       INTEGER,
                       quantity
                       INTEGER,
                       total_amount
                       DECIMAL
                   (
                       10,
                       2
                   ),
                       status TEXT DEFAULT 'pending',
                       telegram_username TEXT,
                       notes TEXT,
                       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                       FOREIGN KEY
                   (
                       product_id
                   ) REFERENCES products
                   (
                       id
                   )
                       )
                   ''')

    # Create default admin user
    default_password = hashlib.sha256("admin123".encode()).hexdigest()
    cursor.execute('''
                   INSERT
                   OR IGNORE INTO admin_users (username, password_hash, email) 
        VALUES (?, ?, ?)
                   ''', ("admin", default_password, "admin@giftshop.com"))

    # Insert sample categories
    sample_categories = [
        ("Electronics", "Electronic gadgets and devices"),
        ("Home & Garden", "Home decoration and garden items"),
        ("Fashion", "Clothing and accessories"),
        ("Toys & Games", "Toys and gaming items"),
        ("Books", "Books and educational materials")
    ]

    for category in sample_categories:
        cursor.execute('INSERT OR IGNORE INTO categories (name, description) VALUES (?, ?)', category)

    conn.commit()
    conn.close()


# Initialize database
init_db()


# Pydantic models
class ProductBase(BaseModel):
    name: str
    description: Optional[str] = None
    price: float
    category: Optional[str] = None
    stock_quantity: int = 0
    is_active: bool = True


class ProductCreate(ProductBase):
    pass


class ProductUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    price: Optional[float] = None
    category: Optional[str] = None
    stock_quantity: Optional[int] = None
    is_active: Optional[bool] = None


class Product(ProductBase):
    id: int
    image_url: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class CategoryBase(BaseModel):
    name: str
    description: Optional[str] = None


class CategoryCreate(CategoryBase):
    pass


class Category(CategoryBase):
    id: int
    created_at: datetime


class AdminLogin(BaseModel):
    username: str
    password: str


class AdminCreate(BaseModel):
    username: str
    password: str
    email: Optional[str] = None


class OrderCreate(BaseModel):
    customer_name: str
    customer_contact: str
    product_id: int
    quantity: int
    telegram_username: Optional[str] = None
    notes: Optional[str] = None


class Order(BaseModel):
    id: int
    customer_name: str
    customer_contact: str
    product_id: int
    quantity: int
    total_amount: float
    status: str
    telegram_username: Optional[str]
    notes: Optional[str]
    created_at: datetime


# Utility functions
def get_db_connection():
    conn = sqlite3.connect('giftshop.db')
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return username
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# API Endpoints

# Public endpoints
@app.get("/")
async def root():
    return {"message": "Gift Shop API", "telegram_channel": TELEGRAM_CHANNEL}


@app.get("/products/", response_model=List[Product])
async def get_products(skip: int = 0, limit: int = 100, category: Optional[str] = None):
    conn = get_db_connection()
    query = "SELECT * FROM products WHERE is_active = 1"
    params = []

    if category:
        query += " AND category = ?"
        params.append(category)

    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, skip])

    products = conn.execute(query, params).fetchall()
    conn.close()

    return [dict(product) for product in products]


@app.get("/products/{product_id}", response_model=Product)
async def get_product(product_id: int):
    conn = get_db_connection()
    product = conn.execute(
        "SELECT * FROM products WHERE id = ? AND is_active = 1",
        (product_id,)
    ).fetchone()
    conn.close()

    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    return dict(product)


@app.get("/categories/", response_model=List[Category])
async def get_categories():
    conn = get_db_connection()
    categories = conn.execute("SELECT * FROM categories ORDER BY name").fetchall()
    conn.close()

    return [dict(category) for category in categories]


@app.post("/orders/", response_model=dict)
async def create_order(order: OrderCreate):
    conn = get_db_connection()

    # Get product details
    product = conn.execute(
        "SELECT * FROM products WHERE id = ? AND is_active = 1",
        (order.product_id,)
    ).fetchone()

    if not product:
        conn.close()
        raise HTTPException(status_code=404, detail="Product not found")

    # Check stock
    if product['stock_quantity'] < order.quantity:
        conn.close()
        raise HTTPException(status_code=400, detail="Insufficient stock")

    # Calculate total amount
    total_amount = product['price'] * order.quantity

    # Create order
    cursor = conn.cursor()
    cursor.execute('''
                   INSERT INTO orders (customer_name, customer_contact, product_id, quantity,
                                       total_amount, telegram_username, notes)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ''', (order.customer_name, order.customer_contact, order.product_id,
                         order.quantity, total_amount, order.telegram_username, order.notes))

    order_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return {
        "message": "Order created successfully! Please contact us on Telegram to complete your order.",
        "order_id": order_id,
        "telegram_channel": TELEGRAM_CHANNEL,
        "total_amount": total_amount
    }


# Auth endpoints
@app.post("/admin/login")
async def admin_login(login_data: AdminLogin):
    conn = get_db_connection()
    admin = conn.execute(
        "SELECT * FROM admin_users WHERE username = ?",
        (login_data.username,)
    ).fetchone()
    conn.close()

    if not admin or admin['password_hash'] != hash_password(login_data.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token = create_access_token(data={"sub": admin['username']})
    return {"access_token": access_token, "token_type": "bearer"}


# Admin endpoints (protected)
@app.post("/admin/products/", response_model=Product)
async def create_product(product: ProductCreate, admin: str = Depends(verify_token)):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
                   INSERT INTO products (name, description, price, category, stock_quantity, is_active)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ''', (product.name, product.description, product.price, product.category,
                         product.stock_quantity, product.is_active))

    product_id = cursor.lastrowid
    conn.commit()

    # Get the created product
    new_product = conn.execute(
        "SELECT * FROM products WHERE id = ?",
        (product_id,)
    ).fetchone()
    conn.close()

    return dict(new_product)


@app.put("/admin/products/{product_id}", response_model=Product)
async def update_product(product_id: int, product_update: ProductUpdate, admin: str = Depends(verify_token)):
    conn = get_db_connection()

    # Check if product exists
    existing_product = conn.execute(
        "SELECT * FROM products WHERE id = ?",
        (product_id,)
    ).fetchone()

    if not existing_product:
        conn.close()
        raise HTTPException(status_code=404, detail="Product not found")

    # Build update query
    update_fields = []
    params = []

    for field, value in product_update.dict(exclude_unset=True).items():
        update_fields.append(f"{field} = ?")
        params.append(value)

    if update_fields:
        params.append(product_id)
        query = f"UPDATE products SET {', '.join(update_fields)}, updated_at = CURRENT_TIMESTAMP WHERE id = ?"
        conn.execute(query, params)
        conn.commit()

    # Get updated product
    updated_product = conn.execute(
        "SELECT * FROM products WHERE id = ?",
        (product_id,)
    ).fetchone()
    conn.close()

    return dict(updated_product)


@app.delete("/admin/products/{product_id}")
async def delete_product(product_id: int, admin: str = Depends(verify_token)):
    conn = get_db_connection()

    result = conn.execute(
        "UPDATE products SET is_active = 0 WHERE id = ?",
        (product_id,)
    )

    if result.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="Product not found")

    conn.commit()
    conn.close()

    return {"message": "Product deleted successfully"}


@app.post("/admin/upload-image/{product_id}")
async def upload_product_image(product_id: int, file: UploadFile = File(...), admin: str = Depends(verify_token)):
    # Validate file type
    if not file.content_type.startswith('image/'):
        raise HTTPException(status_code=400, detail="File must be an image")

    # Generate unique filename
    file_extension = Path(file.filename).suffix
    unique_filename = f"{uuid.uuid4()}{file_extension}"
    file_path = f"uploads/{unique_filename}"

    # Save file
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # Update product with image URL
    conn = get_db_connection()
    image_url = f"/static/{unique_filename}"

    result = conn.execute(
        "UPDATE products SET image_url = ? WHERE id = ?",
        (image_url, product_id)
    )

    if result.rowcount == 0:
        conn.close()
        # Remove uploaded file if product doesn't exist
        os.remove(file_path)
        raise HTTPException(status_code=404, detail="Product not found")

    conn.commit()
    conn.close()

    return {"message": "Image uploaded successfully", "image_url": image_url}


@app.get("/admin/products/", response_model=List[Product])
async def get_all_products_admin(admin: str = Depends(verify_token)):
    conn = get_db_connection()
    products = conn.execute("SELECT * FROM products ORDER BY created_at DESC").fetchall()
    conn.close()

    return [dict(product) for product in products]


@app.get("/admin/orders/", response_model=List[Order])
async def get_orders(admin: str = Depends(verify_token)):
    conn = get_db_connection()
    orders = conn.execute("SELECT * FROM orders ORDER BY created_at DESC").fetchall()
    conn.close()

    return [dict(order) for order in orders]


@app.put("/admin/orders/{order_id}/status")
async def update_order_status(order_id: int, status: str, admin: str = Depends(verify_token)):
    conn = get_db_connection()

    result = conn.execute(
        "UPDATE orders SET status = ? WHERE id = ?",
        (status, order_id)
    )

    if result.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="Order not found")

    conn.commit()
    conn.close()

    return {"message": "Order status updated successfully"}


@app.post("/admin/categories/", response_model=Category)
async def create_category(category: CategoryCreate, admin: str = Depends(verify_token)):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            "INSERT INTO categories (name, description) VALUES (?, ?)",
            (category.name, category.description)
        )
        category_id = cursor.lastrowid
        conn.commit()

        new_category = conn.execute(
            "SELECT * FROM categories WHERE id = ?",
            (category_id,)
        ).fetchone()
        conn.close()

        return dict(new_category)
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail="Category already exists")


@app.get("/admin/dashboard/stats")
async def get_dashboard_stats(admin: str = Depends(verify_token)):
    conn = get_db_connection()

    # Get various statistics
    total_products = conn.execute("SELECT COUNT(*) as count FROM products WHERE is_active = 1").fetchone()['count']
    total_orders = conn.execute("SELECT COUNT(*) as count FROM orders").fetchone()['count']
    pending_orders = conn.execute("SELECT COUNT(*) as count FROM orders WHERE status = 'pending'").fetchone()['count']
    total_revenue = \
    conn.execute("SELECT COALESCE(SUM(total_amount), 0) as revenue FROM orders WHERE status = 'completed'").fetchone()[
        'revenue']

    conn.close()

    return {
        "total_products": total_products,
        "total_orders": total_orders,
        "pending_orders": pending_orders,
        "total_revenue": float(total_revenue),
        "telegram_channel": TELEGRAM_CHANNEL
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)