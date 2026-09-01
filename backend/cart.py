from flask import Flask, jsonify
from flask_cors import CORS
import sqlite3
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

DB_FILE = "cart.db"  # SQLite database file

# --- Database setup (run once to create table and insert sample data) ---
def init_db():
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cartItems (
                id TEXT PRIMARY KEY,
                productName TEXT NOT NULL,
                customer TEXT NOT NULL,
                quantity INTEGER NOT NULL,
                price REAL NOT NULL,
                status TEXT NOT NULL
            )
        ''')

        # Insert sample data if table is empty
        cursor.execute("SELECT COUNT(*) FROM cartItems")
        count = cursor.fetchone()[0]
        if count == 0:
            sample_data = [
                ("ITEM-001", "SecureWipe Pro License", "Wayne Enterprises", 5, 499.99, "Processing"),
                ("ITEM-002", "Hardware Destruction Voucher", "Cyberdyne Systems", 1, 2500.00, "Completed")
            ]
            cursor.executemany("INSERT INTO cartItems VALUES (?, ?, ?, ?, ?, ?)", sample_data)
            conn.commit()
            logger.info("Sample data inserted into cartItems table")
        conn.close()
    except Exception as e:
        logger.error(f"Database initialization error: {e}")

# Initialize DB
init_db()

# --- Endpoint ---
@app.route("/getCartItems", methods=["GET"])
def get_cart_items():
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row  # Return dict-like rows
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM cartItems")
        rows = cursor.fetchall()
        conn.close()

        cart_items = [dict(row) for row in rows]
        return jsonify({"cartItems": cart_items}), 200
    except Exception as e:
        logger.error(f"Error fetching cart items: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    logger.info("🚀 Starting server on port 9684")
    app.run(host="0.0.0.0", port=9684)
