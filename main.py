import psycopg2
import psycopg2.extras
from fastapi import FastAPI, HTTPException, Depends, status, File, UploadFile, Form
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from psycopg2 import IntegrityError
from pydantic import BaseModel
from typing import List, Optional
import hashlib
import jwt
from datetime import datetime, timedelta
import os
import uuid
import shutil
from pathlib import Path
from dotenv import load_dotenv

# Config
SECRET_KEY = "your-secret-key-change-this-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
TELEGRAM_CHANNEL = "@amoragifts"

os.makedirs("uploads", exist_ok=True)
os.makedirs("static", exist_ok=True)

app = FastAPI(title="Gift Shop API", description="Backend API for Gift Shop Website")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: productionda frontend domenini yoz
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="uploads"), name="static")

security = HTTPBearer()
load_dotenv()

# DB connection
def get_db_connection():
    conn = psycopg2.connect(os.environ["DATABASE_URL"])
    return conn

# DB init
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            description TEXT,
            price DECIMAL(10,2) NOT NULL,
            category VARCHAR(255),
            image_url TEXT,
            stock_quantity INTEGER DEFAULT 0,
            is_active BOOLEAN DEFAULT TRUE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS admin_users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(100) UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS categories (
            id SERIAL PRIMARY KEY,
            name VARCHAR(100) UNIQUE NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS orders (
            id SERIAL PRIMARY KEY,
            customer_name VARCHAR(255),
            customer_contact VARCHAR(255),
            product_id INTEGER REFERENCES products(id),
            quantity INTEGER,
            total_amount DECIMAL(10,2),
            status VARCHAR(50) DEFAULT 'pending',
            telegram_username VARCHAR(255),
            notes TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Default admin
    default_password = hashlib.sha256("admin123".encode()).hexdigest()
    cursor.execute('''
        INSERT INTO admin_users (username, password_hash, email)
        VALUES (%s, %s, %s)
        ON CONFLICT (username) DO NOTHING
    ''', ("admin", default_password, "admin@giftshop.com"))

    conn.commit()
    cursor.close()
    conn.close()

init_db()

# Models
class ProductBase(BaseModel):
    name: str
    description: Optional[str] = None
    price: float
    category: Optional[str] = None
    stock_quantity: int = 0
    is_active: bool = True

class ProductCreate(ProductBase): pass
class ProductUpdate(ProductBase): pass

class Product(ProductBase):
    id: int
    image_url: Optional[str] = None
    created_at: datetime
    updated_at: datetime

class CategoryBase(BaseModel):
    name: str
    description: Optional[str] = None

class CategoryCreate(CategoryBase): pass
class Category(CategoryBase):
    id: int
    created_at: datetime

class AdminLogin(BaseModel):
    username: str
    password: str

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

# Utils
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

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
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    query = "SELECT * FROM products WHERE is_active = TRUE"
    params = []

    if category:
        query += " AND category = %s"
        params.append(category)

    query += " ORDER BY created_at DESC LIMIT %s OFFSET %s"
    params.extend([limit, skip])

    cursor.execute(query, tuple(params))
    products = cursor.fetchall()
    cursor.close()
    conn.close()

    return products

@app.get("/categories/", response_model=List[Category])
async def get_categories():
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute("SELECT * FROM categories ORDER BY name")
    categories = cursor.fetchall()
    cursor.close()
    conn.close()
    return categories

@app.get("/categories/", response_model=List[Category])
async def get_categories():
    conn = get_db_connection()
    categories = conn.execute("SELECT * FROM categories ORDER BY name").fetchall()
    conn.close()

    return [dict(category) for category in categories]


@app.post("/orders/", response_model=dict)
async def create_order(order: OrderCreate):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    # Get product
    cursor.execute("SELECT * FROM products WHERE id = %s AND is_active = TRUE", (order.product_id,))
    product = cursor.fetchone()

    if not product:
        cursor.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Product not found")

    if product["stock_quantity"] < order.quantity:
        cursor.close()
        conn.close()
        raise HTTPException(status_code=400, detail="Insufficient stock")

    total_amount = float(product["price"]) * order.quantity

    cursor.execute('''
        INSERT INTO orders (customer_name, customer_contact, product_id, quantity,
                            total_amount, telegram_username, notes)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        RETURNING id
    ''', (order.customer_name, order.customer_contact, order.product_id,
          order.quantity, total_amount, order.telegram_username, order.notes))

    order_id = cursor.fetchone()["id"]
    conn.commit()
    cursor.close()
    conn.close()

    return {
        "message": "Order created successfully! Please contact us on Telegram to complete your order.",
        "order_id": order_id,
        "telegram_channel": TELEGRAM_CHANNEL,
        "total_amount": total_amount
    }


# Auth endpoints
@app.post("/admin/login")
def admin_login(data: AdminLogin):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cursor.execute("SELECT * FROM admin_users WHERE username = %s", (data.username,))
    admin = cursor.fetchone()

    if not admin:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    if admin["password_hash"] != hash_password(data.password):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = create_access_token({"sub": admin["username"]})
    cursor.close()
    conn.close()
    return {"message": "Login successful", "access_token": token}



# Admin endpoints (protected)
@app.post("/admin/products/", response_model=Product)
async def create_product(product: ProductCreate, admin: str = Depends(verify_token)):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cursor.execute('''
        INSERT INTO products (name, description, price, category, stock_quantity, is_active)
        VALUES (%s, %s, %s, %s, %s, %s)
        RETURNING id
    ''', (product.name, product.description, product.price, product.category,
          product.stock_quantity, product.is_active))

    product_id = cursor.fetchone()["id"]
    conn.commit()

    cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,))
    new_product = cursor.fetchone()

    cursor.close()
    conn.close()
    return new_product


@app.put("/admin/products/{product_id}", response_model=Product)
async def update_product(product_id: int, product_update: ProductUpdate, admin: str = Depends(verify_token)):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,))
    existing_product = cursor.fetchone()

    if not existing_product:
        cursor.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Product not found")

    update_fields = []
    params = []

    for field, value in product_update.dict(exclude_unset=True).items():
        update_fields.append(f"{field} = %s")
        params.append(value)

    if update_fields:
        params.append(product_id)
        query = f"UPDATE products SET {', '.join(update_fields)}, updated_at = CURRENT_TIMESTAMP WHERE id = %s"
        cursor.execute(query, tuple(params))
        conn.commit()

    cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,))
    updated_product = cursor.fetchone()

    cursor.close()
    conn.close()
    return updated_product


@app.delete("/admin/products/{product_id}")
async def delete_product(product_id: int, admin: str = Depends(verify_token)):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE products SET is_active = FALSE WHERE id = %s", (product_id,))
    if cursor.rowcount == 0:
        conn.rollback()
        cursor.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Product not found")

    conn.commit()
    cursor.close()
    conn.close()
    return {"message": "Product deleted successfully"}



@app.post("/admin/upload-image/{product_id}")
async def upload_product_image(product_id: int, file: UploadFile = File(...), admin: str = Depends(verify_token)):
    if not file.content_type.startswith('image/'):
        raise HTTPException(status_code=400, detail="File must be an image")

    file_extension = Path(file.filename).suffix
    unique_filename = f"{uuid.uuid4()}{file_extension}"
    file_path = f"uploads/{unique_filename}"

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    conn = get_db_connection()
    cursor = conn.cursor()
    image_url = f"/static/{unique_filename}"
    cursor.execute("UPDATE products SET image_url = %s WHERE id = %s", (image_url, product_id))

    if cursor.rowcount == 0:
        conn.rollback()
        cursor.close()
        conn.close()
        os.remove(file_path)
        raise HTTPException(status_code=404, detail="Product not found")

    conn.commit()
    cursor.close()
    conn.close()
    return {"message": "Image uploaded successfully", "image_url": image_url}


@app.get("/admin/products/", response_model=List[Product])
async def get_all_products_admin(admin: str = Depends(verify_token)):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute("SELECT * FROM products ORDER BY created_at DESC")
    products = cursor.fetchall()
    cursor.close()
    conn.close()
    return products


@app.get("/admin/orders/", response_model=List[Order])
async def get_orders(admin: str = Depends(verify_token)):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cursor.execute("SELECT * FROM orders ORDER BY created_at DESC")
    orders = cursor.fetchall()
    cursor.close()
    conn.close()
    return orders


@app.put("/admin/orders/{order_id}/status")
async def update_order_status(order_id: int, status: str, admin: str = Depends(verify_token)):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE orders SET status = %s WHERE id = %s", (status, order_id))
    if cursor.rowcount == 0:
        conn.rollback()
        cursor.close()
        conn.close()
        raise HTTPException(status_code=404, detail="Order not found")

    conn.commit()
    cursor.close()
    conn.close()
    return {"message": "Order status updated successfully"}

@app.post("/admin/categories/", response_model=Category)
async def create_category(category: CategoryCreate, admin: str = Depends(verify_token)):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    try:
        cursor.execute("INSERT INTO categories (name, description) VALUES (%s, %s) RETURNING id",
                       (category.name, category.description))
        category_id = cursor.fetchone()["id"]
        conn.commit()

        cursor.execute("SELECT * FROM categories WHERE id = %s", (category_id,))
        new_category = cursor.fetchone()

        cursor.close()
        conn.close()
        return new_category
    except IntegrityError:
        conn.rollback()
        cursor.close()
        conn.close()
        raise HTTPException(status_code=400, detail="Category already exists")

@app.get("/admin/dashboard/stats")
async def get_dashboard_stats(admin: str = Depends(verify_token)):
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    cursor.execute("SELECT COUNT(*) as count FROM products WHERE is_active = TRUE")
    total_products = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) as count FROM orders")
    total_orders = cursor.fetchone()["count"]

    cursor.execute("SELECT COUNT(*) as count FROM orders WHERE status = 'pending'")
    pending_orders = cursor.fetchone()["count"]

    cursor.execute("SELECT COALESCE(SUM(total_amount), 0) as revenue FROM orders WHERE status = 'completed'")
    total_revenue = float(cursor.fetchone()["revenue"])

    cursor.close()
    conn.close()

    return {
        "total_products": total_products,
        "total_orders": total_orders,
        "pending_orders": pending_orders,
        "total_revenue": total_revenue,
        "telegram_channel": TELEGRAM_CHANNEL
    }


if __name__ == "__main__":
    import uvicorn
    import os

    port = int(os.environ.get("PORT", 8000))  # Render PORT beradi, lokalda esa 8000 ishlaydi
    uvicorn.run(app, host="0.0.0.0", port=port)
