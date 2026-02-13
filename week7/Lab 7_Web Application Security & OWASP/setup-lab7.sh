#!/bin/bash

# Lab 7 VulnBlog - Quick Setup Script
# ENGSE214 - Web Application Security

echo "╔════════════════════════════════════════════════════════════╗"
echo "║                                                            ║"
echo "║           🚨 VulnBlog - Quick Setup Script                 ║"
echo "║                                                            ║"
echo "║  This script will set up the vulnerable blog system       ║"
echo "║  for ENGSE214 Lab 7.                                       ║"
echo "║                                                            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Check if Node.js is installed
echo "📋 Checking prerequisites..."
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed!"
    echo "   Please install Node.js from: https://nodejs.org/"
    exit 1
fi

NODE_VERSION=$(node -v)
echo "✅ Node.js $NODE_VERSION found"

if ! command -v npm &> /dev/null; then
    echo "❌ npm is not installed!"
    exit 1
fi

NPM_VERSION=$(npm -v)
echo "✅ npm $NPM_VERSION found"
echo ""

# Create project directory
echo "📁 Creating project directory..."
PROJECT_DIR="lab7-vulnblog"

if [ -d "$PROJECT_DIR" ]; then
    echo "⚠️  Directory $PROJECT_DIR already exists!"
    read -p "   Do you want to remove it and start fresh? (y/n): " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$PROJECT_DIR"
        echo "   Old directory removed."
    else
        echo "   Setup cancelled."
        exit 0
    fi
fi

mkdir -p "$PROJECT_DIR"
cd "$PROJECT_DIR" || exit

echo "✅ Created directory: $PROJECT_DIR"
echo ""

# Initialize npm project
echo "📦 Initializing npm project..."
npm init -y > /dev/null 2>&1
echo "✅ package.json created"
echo ""

# Install dependencies
echo "📥 Installing dependencies..."
echo "   This may take a few minutes..."
npm install express sqlite3 body-parser cookie-session --silent

if [ $? -eq 0 ]; then
    echo "✅ Dependencies installed successfully"
else
    echo "❌ Failed to install dependencies"
    echo "   Try running: npm install --legacy-peer-deps"
    exit 1
fi
echo ""

# Create directory structure
echo "📂 Creating project structure..."
mkdir -p public/css
mkdir -p public/js
mkdir -p routes
echo "✅ Directory structure created"
echo ""

# Create database.js
echo "📄 Creating database.js..."
cat > database.js << 'EOF'
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./database.db');

db.serialize(() => {
    // Users table
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            bio TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Posts table
    db.run(`
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `);

    // Comments table
    db.run(`
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            post_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (post_id) REFERENCES posts(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `);

    // Insert sample data
    const sampleUsers = [
        ['admin', 'admin123', 'admin@vulnblog.com', 'System Administrator'],
        ['alice', 'alice123', 'alice@example.com', 'Security Researcher'],
        ['bob', 'bob123', 'bob@example.com', 'Web Developer']
    ];

    const insertUser = db.prepare('INSERT OR IGNORE INTO users (username, password, email, bio) VALUES (?, ?, ?, ?)');
    sampleUsers.forEach(user => insertUser.run(user));
    insertUser.finalize();

    // Insert sample posts
    const samplePosts = [
        [1, 'Welcome to VulnBlog!', 'This is a deliberately vulnerable blog system for educational purposes. Have fun learning web security!'],
        [2, 'Introduction to Web Security', 'Understanding OWASP Top 10 is crucial for any web developer. Let\'s explore common vulnerabilities.'],
        [1, 'SQL Injection 101', 'SQL Injection is one of the most dangerous web vulnerabilities. Always use parameterized queries!']
    ];

    const insertPost = db.prepare('INSERT OR IGNORE INTO posts (user_id, title, content) VALUES (?, ?, ?)');
    samplePosts.forEach(post => insertPost.run(post));
    insertPost.finalize();

    console.log('✅ Database initialized with sample data');
});

module.exports = db;
EOF

echo "✅ database.js created"
echo ""

# Create basic HTML files
echo "📄 Creating HTML files..."

# index.html (basic version)
cat > public/index.html << 'EOF'
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnBlog - Home</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
    <nav class="navbar">
        <div class="container">
            <div class="nav-brand">
                <h1>🚨 VulnBlog</h1>
                <span class="badge-warning">Educational Only</span>
            </div>
            <div class="nav-menu">
                <a href="/">Home</a>
                <a href="/login.html">Login</a>
                <a href="/register.html">Register</a>
            </div>
        </div>
    </nav>

    <div class="container">
        <div class="hero">
            <h2>Welcome to VulnBlog</h2>
            <p>A deliberately vulnerable blog system for learning web security</p>
        </div>

        <div class="posts-section">
            <h3>Recent Posts</h3>
            <div id="postsList" class="posts-list">
                <p>Loading posts...</p>
            </div>
        </div>
    </div>

    <footer>
        <p>⚠️ VulnBlog - For Educational Purposes Only | ENGSE214 Lab 7</p>
    </footer>

    <script>
        loadPosts();

        async function loadPosts() {
            try {
                const response = await fetch('/api/posts');
                const posts = await response.json();
                displayPosts(posts);
            } catch (error) {
                console.error('Error:', error);
            }
        }

        function displayPosts(posts) {
            const postsList = document.getElementById('postsList');
            if (posts.length === 0) {
                postsList.innerHTML = '<p>No posts yet.</p>';
                return;
            }
            postsList.innerHTML = posts.map(post => `
                <div class="post-card">
                    <h4>${escapeHtml(post.title)}</h4>
                    <p class="post-meta">By ${escapeHtml(post.username)}</p>
                    <p>${escapeHtml(post.content.substring(0, 100))}...</p>
                </div>
            `).join('');
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
    </script>
</body>
</html>
EOF

# Basic CSS
cat > public/css/style.css << 'EOF'
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    line-height: 1.6;
    color: #333;
    background-color: #f4f4f4;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
}

.navbar {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 1rem 0;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}

.nav-brand {
    display: flex;
    align-items: center;
    gap: 10px;
}

.badge-warning {
    background-color: #ff6b6b;
    color: white;
    padding: 2px 8px;
    border-radius: 12px;
    font-size: 0.75rem;
}

.navbar .container {
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.nav-menu {
    display: flex;
    gap: 20px;
}

.nav-menu a {
    color: white;
    text-decoration: none;
    padding: 8px 16px;
    border-radius: 4px;
}

.hero {
    background: white;
    padding: 40px;
    border-radius: 8px;
    text-align: center;
    margin: 20px 0;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}

.posts-list {
    display: grid;
    gap: 20px;
}

.post-card {
    background: white;
    padding: 20px;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}

.post-meta {
    color: #666;
    font-size: 0.9rem;
}

footer {
    background: #333;
    color: white;
    text-align: center;
    padding: 20px 0;
    margin-top: 40px;
}
EOF

echo "✅ HTML/CSS files created"
echo ""

# Create .gitignore
cat > .gitignore << 'EOF'
node_modules/
database.db
*.log
.DS_Store
EOF

echo "✅ .gitignore created"
echo ""

# Update package.json scripts
echo "📝 Updating package.json scripts..."
cat > package.json << 'EOF'
{
  "name": "lab7-vulnblog",
  "version": "1.0.0",
  "description": "Vulnerable Blog System for ENGSE214 Lab 7",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  },
  "keywords": ["security", "owasp", "education"],
  "author": "",
  "license": "MIT",
  "dependencies": {
    "body-parser": "^1.20.2",
    "cookie-session": "^2.0.0",
    "express": "^4.18.2",
    "sqlite3": "^5.1.6"
  }
}
EOF

echo "✅ package.json updated"
echo ""

# Create README
cat > README.md << 'EOF'
# VulnBlog - Vulnerable Blog System

⚠️ **WARNING: This application contains intentional security vulnerabilities for educational purposes. DO NOT deploy to production!**

## ENGSE214 Lab 7: Web Application Security

### Setup Instructions

1. Install dependencies:
```bash
npm install
```

2. Start the server:
```bash
npm start
```

3. Open browser: http://localhost:3000

### Test Accounts

- Username: `admin` / Password: `admin123`
- Username: `alice` / Password: `alice123`
- Username: `bob` / Password: `bob123`

### Vulnerabilities to Find

- [ ] SQL Injection in login
- [ ] SQL Injection in search
- [ ] Stored XSS in comments
- [ ] Reflected XSS in search
- [ ] Broken Access Control

### Files to Create

You need to create `server.js` following the lab instructions.

Good luck! 🎯
EOF

echo "✅ README.md created"
echo ""

# Final instructions
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                                                            ║"
echo "║           ✅ Setup Complete!                                ║"
echo "║                                                            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "📋 Next steps:"
echo ""
echo "1. cd $PROJECT_DIR"
echo "2. Create server.js (follow lab instructions)"
echo "3. npm start"
echo "4. Open http://localhost:3000"
echo ""
echo "📖 See lab7_instructions.md for detailed guide"
echo ""
echo "🎯 Good luck with the lab!"
echo ""
