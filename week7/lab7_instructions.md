# Lab 7: Web Application Security - Vulnerable Blog System
## ENGSE214 – ความมั่นคงปลอดภัยทางไซเบอร์เบื้องต้น

**เวลาที่ใช้:** 2-3 ชั่วโมง  
**คะแนน:** 10 คะแนน  
**CLO ที่เกี่ยวข้อง:** CLO2, CLO3

---

## 🎯 วัตถุประสงค์

Lab นี้จะช่วยให้คุณ:
1. ✅ เข้าใจช่องโหว่ SQL Injection และ Cross-Site Scripting (XSS) อย่างลึกซึ้ง
2. ✅ ฝึกหาช่องโหว่ในระบบ Web Application จริง
3. ✅ นำเทคนิคการป้องกันมาใช้งานจริง (Parameterized Query, Output Encoding)
4. ✅ เข้าใจความแตกต่างระหว่าง Vulnerable Code และ Secure Code
5. ✅ ฝึกเขียน Security Report ตามมาตรฐาน

---

## 📦 ภาพรวมระบบ

คุณจะได้ทำงานกับ **VulnBlog** - ระบบ Blog แบบง่ายที่จงใจสร้างให้มีช่องโหว่ความปลอดภัยตาม OWASP Top 10

```
┌─────────────────────────────────────────────────────────────────┐
│                        🖥️ VulnBlog System                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  👤 Features:                                                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ Registration │  │    Login     │  │  Blog Posts  │          │
│  │   & Login    │  │   System     │  │   Creation   │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │   Comments   │  │    Search    │  │    Profile   │          │
│  │    System    │  │   Feature    │  │   Viewing    │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│                                                                 │
│  🚨 Vulnerabilities ที่ซ่อนอยู่:                                  │
│  • SQL Injection (หลายจุด)                                      │
│  • Stored XSS                                                   │
│  • Reflected XSS                                                │
│  • Broken Access Control                                       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Stack เทคโนโลยี

```
Backend:    Node.js + Express.js
Database:   SQLite3
Frontend:   HTML5 + CSS3 + Vanilla JavaScript
```

---

## 📋 Part 1: Setup & Installation (15 นาที)

### 1.1 ติดตั้ง Dependencies

สร้าง Project Directory:
```bash
mkdir lab7-vulnblog
cd lab7-vulnblog
```

สร้าง `package.json`:
```bash
npm init -y
```

ติดตั้ง Packages:
```bash
npm install express sqlite3 body-parser cookie-session
npm install --save-dev nodemon
```

### 1.2 โครงสร้าง Project

```
lab7-vulnblog/
├── package.json
├── server.js                    # Main server file
├── database.js                  # Database setup
├── routes/
│   ├── auth.js                 # Login/Register routes
│   ├── posts.js                # Blog post routes
│   └── users.js                # User profile routes
├── public/
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── post.html
│   ├── profile.html
│   ├── css/
│   │   └── style.css
│   └── js/
│       ├── main.js
│       ├── auth.js
│       └── posts.js
└── database.db                  # SQLite database (auto-created)
```

---

## 🔧 Part 2: การสร้างระบบ (45 นาที)

### 2.1 สร้าง Backend

#### ไฟล์ที่ 1: `database.js`
สร้างไฟล์นี้เพื่อจัดการฐานข้อมูล:

```javascript
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

    console.log('✅ Database initialized successfully');
});

module.exports = db;
```

#### ไฟล์ที่ 2: `server.js` (VULNERABLE VERSION)

```javascript
const express = require('express');
const bodyParser = require('body-parser');
const cookieSession = require('cookie-session');
const db = require('./database');

const app = express();
const PORT = 3000;

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieSession({
    name: 'session',
    keys: ['secret-key-123'], // Weak secret!
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
}));

// Serve static files
app.use(express.static('public'));

// ============================================
// 🚨 VULNERABLE: SQL Injection in Login
// ============================================
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    // VULNERABLE: String concatenation instead of parameterized query
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    
    console.log('Login query:', query); // For debugging
    
    db.get(query, (err, user) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        
        if (user) {
            req.session.userId = user.id;
            req.session.username = user.username;
            res.json({ 
                success: true, 
                message: 'Login successful',
                username: user.username 
            });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    });
});

// ============================================
// 🚨 VULNERABLE: SQL Injection in Registration
// ============================================
app.post('/api/register', (req, res) => {
    const { username, password, email } = req.body;
    
    // VULNERABLE: String concatenation
    const query = `INSERT INTO users (username, password, email) VALUES ('${username}', '${password}', '${email}')`;
    
    db.run(query, function(err) {
        if (err) {
            return res.status(400).json({ error: 'Username already exists or invalid data' });
        }
        res.json({ 
            success: true, 
            message: 'Registration successful',
            userId: this.lastID 
        });
    });
});

// ============================================
// Check authentication
// ============================================
app.get('/api/auth/check', (req, res) => {
    if (req.session.userId) {
        res.json({ 
            authenticated: true, 
            username: req.session.username,
            userId: req.session.userId
        });
    } else {
        res.json({ authenticated: false });
    }
});

// Logout
app.post('/api/logout', (req, res) => {
    req.session = null;
    res.json({ success: true });
});

// ============================================
// 🚨 VULNERABLE: SQL Injection in Search
// ============================================
app.get('/api/posts/search', (req, res) => {
    const keyword = req.query.q || '';
    
    // VULNERABLE: String concatenation in LIKE clause
    const query = `
        SELECT posts.*, users.username 
        FROM posts 
        JOIN users ON posts.user_id = users.id 
        WHERE posts.title LIKE '%${keyword}%' OR posts.content LIKE '%${keyword}%'
        ORDER BY posts.created_at DESC
    `;
    
    console.log('Search query:', query);
    
    db.all(query, (err, posts) => {
        if (err) {
            console.error('Search error:', err);
            return res.status(500).json({ error: 'Search failed' });
        }
        res.json(posts);
    });
});

// Get all posts
app.get('/api/posts', (req, res) => {
    const query = `
        SELECT posts.*, users.username 
        FROM posts 
        JOIN users ON posts.user_id = users.id 
        ORDER BY posts.created_at DESC
    `;
    
    db.all(query, (err, posts) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to fetch posts' });
        }
        res.json(posts);
    });
});

// Get single post
app.get('/api/posts/:id', (req, res) => {
    const postId = req.params.id;
    
    // This one is actually safe (using parameterized query)
    const query = `
        SELECT posts.*, users.username 
        FROM posts 
        JOIN users ON posts.user_id = users.id 
        WHERE posts.id = ?
    `;
    
    db.get(query, [postId], (err, post) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to fetch post' });
        }
        if (!post) {
            return res.status(404).json({ error: 'Post not found' });
        }
        res.json(post);
    });
});

// Create new post (requires authentication)
app.post('/api/posts', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    const { title, content } = req.body;
    
    // This one is safe (using parameterized query)
    const query = 'INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)';
    
    db.run(query, [req.session.userId, title, content], function(err) {
        if (err) {
            return res.status(500).json({ error: 'Failed to create post' });
        }
        res.json({ 
            success: true, 
            postId: this.lastID 
        });
    });
});

// ============================================
// 🚨 VULNERABLE: Stored XSS in Comments
// ============================================
app.get('/api/posts/:id/comments', (req, res) => {
    const postId = req.params.id;
    
    const query = `
        SELECT comments.*, users.username 
        FROM comments 
        JOIN users ON comments.user_id = users.id 
        WHERE comments.post_id = ?
        ORDER BY comments.created_at ASC
    `;
    
    db.all(query, [postId], (err, comments) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to fetch comments' });
        }
        res.json(comments);
    });
});

app.post('/api/posts/:id/comments', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    
    const postId = req.params.id;
    const { content } = req.body;
    
    // No XSS protection - stores raw HTML/JavaScript!
    const query = 'INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)';
    
    db.run(query, [postId, req.session.userId, content], function(err) {
        if (err) {
            return res.status(500).json({ error: 'Failed to post comment' });
        }
        res.json({ 
            success: true, 
            commentId: this.lastID 
        });
    });
});

// ============================================
// 🚨 VULNERABLE: Broken Access Control
// ============================================
app.get('/api/users/:id', (req, res) => {
    const userId = req.params.id;
    
    // No authentication check! Anyone can view any profile
    const query = 'SELECT id, username, email, bio, created_at FROM users WHERE id = ?';
    
    db.get(query, [userId], (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to fetch user' });
        }
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json(user);
    });
});

// Update user profile
app.put('/api/users/:id', (req, res) => {
    const userId = req.params.id;
    const { email, bio } = req.body;
    
    // VULNERABLE: No check if userId matches session userId!
    // Anyone can edit anyone's profile!
    const query = 'UPDATE users SET email = ?, bio = ? WHERE id = ?';
    
    db.run(query, [email, bio, userId], (err) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to update profile' });
        }
        res.json({ success: true });
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║           🚨 VulnBlog - Vulnerable Blog System             ║
║                                                            ║
║  Server running at: http://localhost:${PORT}                   ║
║                                                            ║
║  ⚠️  WARNING: This application contains intentional        ║
║      security vulnerabilities for educational purposes.   ║
║      DO NOT use this code in production!                  ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
    `);
});
```

---

## 🎨 Part 3: Frontend Files (ให้พร้อมทำงาน)

### 3.1 `public/index.html`

```html
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
            <div class="nav-menu" id="navMenu">
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

        <div class="search-box">
            <input type="text" id="searchInput" placeholder="Search posts..." />
            <button onclick="searchPosts()">🔍 Search</button>
        </div>

        <div id="searchResults" class="search-results"></div>

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

    <script src="/js/main.js"></script>
    <script>
        // Load posts on page load
        loadPosts();

        async function loadPosts() {
            try {
                const response = await fetch('/api/posts');
                const posts = await response.json();
                displayPosts(posts);
            } catch (error) {
                console.error('Error loading posts:', error);
                document.getElementById('postsList').innerHTML = 
                    '<p class="error">Failed to load posts</p>';
            }
        }

        function displayPosts(posts) {
            const postsList = document.getElementById('postsList');
            
            if (posts.length === 0) {
                postsList.innerHTML = '<p>No posts yet. Be the first to post!</p>';
                return;
            }

            postsList.innerHTML = posts.map(post => `
                <div class="post-card">
                    <h4><a href="/post.html?id=${post.id}">${escapeHtml(post.title)}</a></h4>
                    <p class="post-meta">
                        By ${escapeHtml(post.username)} | 
                        ${new Date(post.created_at).toLocaleDateString('th-TH')}
                    </p>
                    <p class="post-excerpt">${escapeHtml(post.content.substring(0, 150))}...</p>
                </div>
            `).join('');
        }

        async function searchPosts() {
            const keyword = document.getElementById('searchInput').value;
            const resultsDiv = document.getElementById('searchResults');
            
            if (!keyword.trim()) {
                resultsDiv.innerHTML = '';
                return;
            }

            try {
                // 🚨 VULNERABLE: Reflected XSS - keyword is displayed without encoding
                resultsDiv.innerHTML = `<p>Searching for: <strong>"${keyword}"</strong></p>`;
                
                const response = await fetch(`/api/posts/search?q=${encodeURIComponent(keyword)}`);
                const posts = await response.json();
                
                if (posts.length === 0) {
                    resultsDiv.innerHTML += '<p>No posts found</p>';
                } else {
                    resultsDiv.innerHTML += `<p>Found ${posts.length} result(s)</p>`;
                    displayPosts(posts);
                }
            } catch (error) {
                console.error('Search error:', error);
                resultsDiv.innerHTML = '<p class="error">Search failed</p>';
            }
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
    </script>
</body>
</html>
```

### 3.2 `public/login.html`

```html
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - VulnBlog</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
    <nav class="navbar">
        <div class="container">
            <div class="nav-brand">
                <h1>🚨 VulnBlog</h1>
            </div>
            <div class="nav-menu">
                <a href="/">Home</a>
                <a href="/register.html">Register</a>
            </div>
        </div>
    </nav>

    <div class="container">
        <div class="auth-container">
            <h2>Login</h2>
            <form id="loginForm" class="auth-form">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required>
                </div>
                
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                </div>

                <button type="submit" class="btn-primary">Login</button>
                
                <div id="message" class="message"></div>
            </form>

            <div class="auth-links">
                <p>Don't have an account? <a href="/register.html">Register here</a></p>
            </div>

            <div class="help-box">
                <h4>🔍 Test Accounts:</h4>
                <ul>
                    <li><strong>admin</strong> / admin123</li>
                    <li><strong>alice</strong> / alice123</li>
                    <li><strong>bob</strong> / bob123</li>
                </ul>
                <p class="hint">💡 Hint: Try SQL Injection payloads!</p>
            </div>
        </div>
    </div>

    <script src="/js/auth.js"></script>
</body>
</html>
```

### 3.3 `public/register.html`

```html
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - VulnBlog</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
    <nav class="navbar">
        <div class="container">
            <div class="nav-brand">
                <h1>🚨 VulnBlog</h1>
            </div>
            <div class="nav-menu">
                <a href="/">Home</a>
                <a href="/login.html">Login</a>
            </div>
        </div>
    </nav>

    <div class="container">
        <div class="auth-container">
            <h2>Create Account</h2>
            <form id="registerForm" class="auth-form">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required>
                </div>
                
                <div class="form-group">
                    <label for="email">Email:</label>
                    <input type="email" id="email" name="email" required>
                </div>
                
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                </div>

                <button type="submit" class="btn-primary">Register</button>
                
                <div id="message" class="message"></div>
            </form>

            <div class="auth-links">
                <p>Already have an account? <a href="/login.html">Login here</a></p>
            </div>
        </div>
    </div>

    <script>
        document.getElementById('registerForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const username = document.getElementById('username').value;
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const messageDiv = document.getElementById('message');

            try {
                const response = await fetch('/api/register', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, email, password })
                });

                const data = await response.json();

                if (response.ok) {
                    messageDiv.className = 'message success';
                    messageDiv.textContent = 'Registration successful! Redirecting to login...';
                    setTimeout(() => {
                        window.location.href = '/login.html';
                    }, 2000);
                } else {
                    messageDiv.className = 'message error';
                    messageDiv.textContent = data.error || 'Registration failed';
                }
            } catch (error) {
                messageDiv.className = 'message error';
                messageDiv.textContent = 'Network error. Please try again.';
            }
        });
    </script>
</body>
</html>
```

### 3.4 `public/dashboard.html`

```html
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - VulnBlog</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
    <nav class="navbar">
        <div class="container">
            <div class="nav-brand">
                <h1>🚨 VulnBlog</h1>
            </div>
            <div class="nav-menu">
                <a href="/">Home</a>
                <a href="/dashboard.html">Dashboard</a>
                <span id="usernameDisplay"></span>
                <a href="#" onclick="logout()">Logout</a>
            </div>
        </div>
    </nav>

    <div class="container">
        <h2>Create New Post</h2>
        
        <form id="createPostForm" class="post-form">
            <div class="form-group">
                <label for="title">Title:</label>
                <input type="text" id="title" required>
            </div>
            
            <div class="form-group">
                <label for="content">Content:</label>
                <textarea id="content" rows="10" required></textarea>
            </div>

            <button type="submit" class="btn-primary">Publish Post</button>
            
            <div id="message" class="message"></div>
        </form>

        <div class="my-posts">
            <h3>My Posts</h3>
            <div id="myPostsList">
                <p>Loading...</p>
            </div>
        </div>
    </div>

    <script src="/js/main.js"></script>
    <script src="/js/posts.js"></script>
</body>
</html>
```

### 3.5 `public/post.html`

```html
<!DOCTYPE html>
<html lang="th">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Post - VulnBlog</title>
    <link rel="stylesheet" href="/css/style.css">
</head>
<body>
    <nav class="navbar">
        <div class="container">
            <div class="nav-brand">
                <h1>🚨 VulnBlog</h1>
            </div>
            <div class="nav-menu">
                <a href="/">Home</a>
                <span id="userMenuPlaceholder"></span>
            </div>
        </div>
    </nav>

    <div class="container">
        <div id="postContent" class="post-detail">
            <p>Loading post...</p>
        </div>

        <div class="comments-section">
            <h3>Comments</h3>
            
            <div id="commentForm" style="display: none;">
                <textarea id="commentInput" rows="3" placeholder="Write a comment..."></textarea>
                <button onclick="submitComment()" class="btn-primary">Post Comment</button>
            </div>
            
            <div id="loginPrompt" style="display: none;">
                <p>Please <a href="/login.html">login</a> to comment</p>
            </div>

            <div id="commentsList" class="comments-list">
                <p>Loading comments...</p>
            </div>
        </div>
    </div>

    <script src="/js/main.js"></script>
    <script>
        let currentPostId;
        let currentUser = null;

        async function checkAuth() {
            try {
                const response = await fetch('/api/auth/check');
                const data = await response.json();
                
                if (data.authenticated) {
                    currentUser = data;
                    document.getElementById('userMenuPlaceholder').innerHTML = `
                        <a href="/dashboard.html">Dashboard</a>
                        <span>${data.username}</span>
                        <a href="#" onclick="logout()">Logout</a>
                    `;
                    document.getElementById('commentForm').style.display = 'block';
                } else {
                    document.getElementById('userMenuPlaceholder').innerHTML = `
                        <a href="/login.html">Login</a>
                    `;
                    document.getElementById('loginPrompt').style.display = 'block';
                }
            } catch (error) {
                console.error('Auth check failed:', error);
            }
        }

        async function loadPost() {
            const urlParams = new URLSearchParams(window.location.search);
            currentPostId = urlParams.get('id');

            if (!currentPostId) {
                document.getElementById('postContent').innerHTML = 
                    '<p class="error">Post not found</p>';
                return;
            }

            try {
                const response = await fetch(`/api/posts/${currentPostId}`);
                const post = await response.json();

                if (response.ok) {
                    document.getElementById('postContent').innerHTML = `
                        <h2>${escapeHtml(post.title)}</h2>
                        <p class="post-meta">
                            By ${escapeHtml(post.username)} | 
                            ${new Date(post.created_at).toLocaleDateString('th-TH')}
                        </p>
                        <div class="post-body">
                            ${escapeHtml(post.content)}
                        </div>
                    `;
                    
                    loadComments();
                } else {
                    document.getElementById('postContent').innerHTML = 
                        '<p class="error">Post not found</p>';
                }
            } catch (error) {
                console.error('Error loading post:', error);
                document.getElementById('postContent').innerHTML = 
                    '<p class="error">Failed to load post</p>';
            }
        }

        async function loadComments() {
            try {
                const response = await fetch(`/api/posts/${currentPostId}/comments`);
                const comments = await response.json();

                const commentsList = document.getElementById('commentsList');

                if (comments.length === 0) {
                    commentsList.innerHTML = '<p>No comments yet. Be the first!</p>';
                    return;
                }

                // 🚨 VULNERABLE: innerHTML with raw comment content = Stored XSS!
                commentsList.innerHTML = comments.map(comment => `
                    <div class="comment">
                        <p class="comment-author">
                            <strong>${escapeHtml(comment.username)}</strong> - 
                            ${new Date(comment.created_at).toLocaleDateString('th-TH')}
                        </p>
                        <p class="comment-content">${comment.content}</p>
                    </div>
                `).join('');
            } catch (error) {
                console.error('Error loading comments:', error);
            }
        }

        async function submitComment() {
            const content = document.getElementById('commentInput').value.trim();

            if (!content) {
                alert('Please write a comment');
                return;
            }

            try {
                const response = await fetch(`/api/posts/${currentPostId}/comments`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ content })
                });

                if (response.ok) {
                    document.getElementById('commentInput').value = '';
                    loadComments();
                } else {
                    alert('Failed to post comment');
                }
            } catch (error) {
                console.error('Error posting comment:', error);
                alert('Network error');
            }
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        // Initialize
        checkAuth();
        loadPost();
    </script>
</body>
</html>
```

### 3.6 `public/css/style.css`

```css
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

/* Navbar */
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

.nav-brand h1 {
    font-size: 1.5rem;
    margin: 0;
}

.badge-warning {
    background-color: #ff6b6b;
    color: white;
    padding: 2px 8px;
    border-radius: 12px;
    font-size: 0.75rem;
    font-weight: bold;
}

.navbar .container {
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.nav-menu {
    display: flex;
    gap: 20px;
    align-items: center;
}

.nav-menu a {
    color: white;
    text-decoration: none;
    padding: 8px 16px;
    border-radius: 4px;
    transition: background 0.3s;
}

.nav-menu a:hover {
    background-color: rgba(255,255,255,0.2);
}

/* Hero Section */
.hero {
    background: white;
    padding: 40px;
    border-radius: 8px;
    text-align: center;
    margin: 20px 0;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}

.hero h2 {
    color: #667eea;
    margin-bottom: 10px;
}

/* Search Box */
.search-box {
    background: white;
    padding: 20px;
    border-radius: 8px;
    margin: 20px 0;
    display: flex;
    gap: 10px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}

.search-box input {
    flex: 1;
    padding: 12px;
    border: 2px solid #ddd;
    border-radius: 4px;
    font-size: 1rem;
}

.search-box button {
    padding: 12px 24px;
    background: #667eea;
    color: white;
    border: none;
    border-radius: 4px;
    cursor: pointer;
    font-size: 1rem;
    transition: background 0.3s;
}

.search-box button:hover {
    background: #764ba2;
}

.search-results {
    background: #fffbea;
    border-left: 4px solid #f39c12;
    padding: 15px;
    margin: 20px 0;
    border-radius: 4px;
}

/* Posts */
.posts-section {
    margin: 20px 0;
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
    transition: transform 0.3s, box-shadow 0.3s;
}

.post-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 15px rgba(0,0,0,0.15);
}

.post-card h4 {
    color: #667eea;
    margin-bottom: 10px;
}

.post-card h4 a {
    color: #667eea;
    text-decoration: none;
}

.post-card h4 a:hover {
    text-decoration: underline;
}

.post-meta {
    color: #666;
    font-size: 0.9rem;
    margin-bottom: 10px;
}

.post-excerpt {
    color: #333;
    line-height: 1.6;
}

/* Post Detail */
.post-detail {
    background: white;
    padding: 30px;
    border-radius: 8px;
    margin: 20px 0;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}

.post-body {
    margin-top: 20px;
    line-height: 1.8;
    white-space: pre-wrap;
}

/* Comments */
.comments-section {
    background: white;
    padding: 30px;
    border-radius: 8px;
    margin: 20px 0;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}

.comments-section h3 {
    color: #667eea;
    margin-bottom: 20px;
}

#commentForm textarea {
    width: 100%;
    padding: 12px;
    border: 2px solid #ddd;
    border-radius: 4px;
    margin-bottom: 10px;
    font-family: inherit;
    resize: vertical;
}

.comments-list {
    margin-top: 20px;
}

.comment {
    background: #f8f9fa;
    padding: 15px;
    border-radius: 4px;
    margin-bottom: 15px;
    border-left: 3px solid #667eea;
}

.comment-author {
    color: #667eea;
    font-weight: bold;
    margin-bottom: 8px;
}

.comment-content {
    color: #333;
    line-height: 1.6;
}

/* Forms */
.auth-container {
    max-width: 500px;
    margin: 40px auto;
    background: white;
    padding: 40px;
    border-radius: 8px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}

.auth-form {
    margin-top: 20px;
}

.form-group {
    margin-bottom: 20px;
}

.form-group label {
    display: block;
    margin-bottom: 8px;
    color: #333;
    font-weight: 500;
}

.form-group input,
.form-group textarea {
    width: 100%;
    padding: 12px;
    border: 2px solid #ddd;
    border-radius: 4px;
    font-size: 1rem;
    font-family: inherit;
}

.form-group input:focus,
.form-group textarea:focus {
    outline: none;
    border-color: #667eea;
}

.btn-primary {
    width: 100%;
    padding: 12px;
    background: #667eea;
    color: white;
    border: none;
    border-radius: 4px;
    font-size: 1rem;
    cursor: pointer;
    transition: background 0.3s;
}

.btn-primary:hover {
    background: #764ba2;
}

.auth-links {
    margin-top: 20px;
    text-align: center;
    color: #666;
}

.auth-links a {
    color: #667eea;
    text-decoration: none;
}

.auth-links a:hover {
    text-decoration: underline;
}

/* Messages */
.message {
    margin-top: 15px;
    padding: 12px;
    border-radius: 4px;
    text-align: center;
}

.message.success {
    background-color: #d4edda;
    color: #155724;
    border: 1px solid #c3e6cb;
}

.message.error {
    background-color: #f8d7da;
    color: #721c24;
    border: 1px solid #f5c6cb;
}

/* Help Box */
.help-box {
    margin-top: 30px;
    padding: 20px;
    background: #fff3cd;
    border-left: 4px solid #ffc107;
    border-radius: 4px;
}

.help-box h4 {
    color: #856404;
    margin-bottom: 10px;
}

.help-box ul {
    list-style: none;
    padding-left: 0;
}

.help-box li {
    padding: 5px 0;
}

.help-box .hint {
    margin-top: 10px;
    font-style: italic;
    color: #856404;
}

/* Footer */
footer {
    background: #333;
    color: white;
    text-align: center;
    padding: 20px 0;
    margin-top: 40px;
}

/* Post Form */
.post-form {
    background: white;
    padding: 30px;
    border-radius: 8px;
    margin: 20px 0;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
}

/* Responsive */
@media (max-width: 768px) {
    .navbar .container {
        flex-direction: column;
        gap: 15px;
    }

    .nav-menu {
        flex-wrap: wrap;
        justify-content: center;
    }

    .search-box {
        flex-direction: column;
    }
}
```

### 3.7 `public/js/main.js`

```javascript
// Common utility functions

async function logout() {
    try {
        await fetch('/api/logout', { method: 'POST' });
        window.location.href = '/';
    } catch (error) {
        console.error('Logout error:', error);
    }
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

async function checkAuth() {
    try {
        const response = await fetch('/api/auth/check');
        const data = await response.json();
        return data.authenticated ? data : null;
    } catch (error) {
        console.error('Auth check failed:', error);
        return null;
    }
}
```

### 3.8 `public/js/auth.js`

```javascript
document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const messageDiv = document.getElementById('message');

    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (response.ok) {
            messageDiv.className = 'message success';
            messageDiv.textContent = 'Login successful! Redirecting...';
            setTimeout(() => {
                window.location.href = '/dashboard.html';
            }, 1000);
        } else {
            messageDiv.className = 'message error';
            messageDiv.textContent = data.error || 'Login failed';
        }
    } catch (error) {
        messageDiv.className = 'message error';
        messageDiv.textContent = 'Network error. Please try again.';
    }
});
```

### 3.9 `public/js/posts.js`

```javascript
async function loadDashboard() {
    const user = await checkAuth();
    
    if (!user) {
        window.location.href = '/login.html';
        return;
    }

    document.getElementById('usernameDisplay').textContent = user.username;
}

document.getElementById('createPostForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const title = document.getElementById('title').value;
    const content = document.getElementById('content').value;
    const messageDiv = document.getElementById('message');

    try {
        const response = await fetch('/api/posts', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ title, content })
        });

        const data = await response.json();

        if (response.ok) {
            messageDiv.className = 'message success';
            messageDiv.textContent = 'Post created successfully!';
            document.getElementById('createPostForm').reset();
            setTimeout(() => {
                window.location.href = `/post.html?id=${data.postId}`;
            }, 1000);
        } else {
            messageDiv.className = 'message error';
            messageDiv.textContent = data.error || 'Failed to create post';
        }
    } catch (error) {
        messageDiv.className = 'message error';
        messageDiv.textContent = 'Network error. Please try again.';
    }
});

// Load dashboard on page load
if (window.location.pathname === '/dashboard.html') {
    loadDashboard();
}
```

---

## 🔍 Part 4: การทดสอบช่องโหว่ (60 นาที)

### Task 1: SQL Injection ใน Login Form (15 นาที)

#### 🎯 เป้าหมาย
Bypass login โดยไม่ต้องรู้ password จริง

#### 💡 Hints
- Server สร้าง SQL query แบบนี้: `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`
- ลอง inject SQL comment (`--`) เพื่อ ignore ส่วน password

#### ✅ Payloads ที่ควรทดลอง

**Payload 1: Classic SQL Injection**
```
Username: admin' OR '1'='1' --
Password: anything
```

**Payload 2: UNION-based**
```
Username: admin' OR 1=1 --
Password: (ไม่สำคัญ)
```

**Payload 3: Comment Injection**
```
Username: admin'/*
Password: */OR/**/1=1--
```

#### 📝 สิ่งที่ต้องบันทึก
1. Payload ที่ใช้สำเร็จ
2. Query ที่แท้จริงที่ถูก execute (ดูจาก console.log)
3. เหตุผลที่ทำงาน

---

### Task 2: SQL Injection ใน Search Feature (20 นาที)

#### 🎯 เป้าหมาย
ดึงข้อมูลจาก table อื่นที่ไม่ควรเข้าถึงได้

#### 💡 Hints
- Search ใช้ LIKE clause: `WHERE title LIKE '%${keyword}%'`
- ลอง UNION SELECT เพื่อดึงข้อมูล users table

#### ✅ Payloads

**Payload 1: Information Gathering**
```
Search: ' UNION SELECT 1,2,3,4,5 --
```
(ดูว่ามีกี่ column ใน result)

**Payload 2: Extract Database Schema**
```
Search: ' UNION SELECT name, sql, '', '', '' FROM sqlite_master WHERE type='table' --
```

**Payload 3: Extract User Passwords**
```
Search: ' UNION SELECT id, username, password, email, '' FROM users --
```

#### 📝 สิ่งที่ต้องบันทึก
1. จำนวน column ที่ต้องใช้ใน UNION
2. ข้อมูล users ที่ดึงได้
3. Table/Column อื่นๆ ที่พบ

---

### Task 3: Stored XSS ใน Comments (15 นาที)

#### 🎯 เป้าหมาย
Inject JavaScript ที่จะ execute เมื่อคนอื่นดู comment

#### ✅ Payloads

**Payload 1: Basic Alert**
```html
<script>alert('XSS Vulnerability!');</script>
```

**Payload 2: Cookie Stealer**
```html
<script>
alert('Your session cookie: ' + document.cookie);
</script>
```

**Payload 3: Phishing (Advanced)**
```html
<div style="background:white; padding:20px; border:2px solid red;">
<h3>⚠️ Session Expired</h3>
<p>Please re-enter your password:</p>
<input type="password" id="fakepass" />
<button onclick="alert('Stolen: ' + document.getElementById('fakepass').value)">Login</button>
</div>
```

**Payload 4: Image-based XSS**
```html
<img src="x" onerror="alert('XSS via image!')">
```

#### 📝 สิ่งที่ต้องบันทึก
1. Payload ที่ execute สำเร็จ
2. ผลกระทบที่เกิดขึ้น (alert, cookie access, etc.)
3. วิธีที่ attacker จะใช้ประโยชน์จริง

---

### Task 4: Reflected XSS ใน Search (10 นาที)

#### 🎯 เป้าหมาย
Inject script ผ่าน search query parameter

#### 💡 Hints
- Search results แสดง: `Searching for: "${keyword}"`
- keyword ไม่ได้ escape ก่อนแสดงผล

#### ✅ Test Cases

ลองค้นหาด้วย:
```html
<script>alert('Reflected XSS')</script>
```

หรือ
```html
<img src=x onerror="alert('XSS')">
```

สังเกตว่า JavaScript execute หรือไม่

#### 📝 สิ่งที่ต้องบันทึก
1. ความแตกต่างระหว่าง Stored XSS และ Reflected XSS
2. วิธีที่ attacker จะส่ง malicious link ให้เหยื่อ

---

## 🛠️ Part 5: การแก้ไขช่องโหว่ (60 นาที)

### Task 5: แก้ SQL Injection (30 นาที)

#### 📝 สิ่งที่ต้องทำ

1. สร้างไฟล์ `server-secure.js` (copy จาก server.js)

2. แก้ไขส่วน Login ให้ใช้ Parameterized Query:

```javascript
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    // ✅ SECURE: ใช้ Parameterized Query
    const query = 'SELECT * FROM users WHERE username = ? AND password = ?';
    
    db.get(query, [username, password], (err, user) => {
        if (err) {
            console.error('Database error:', err);
            return res.status(500).json({ error: 'Database error' });
        }
        
        if (user) {
            req.session.userId = user.id;
            req.session.username = user.username;
            res.json({ 
                success: true, 
                message: 'Login successful',
                username: user.username 
            });
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    });
});
```

3. แก้ไขส่วน Search:

```javascript
app.get('/api/posts/search', (req, res) => {
    const keyword = req.query.q || '';
    
    // ✅ SECURE: ใช้ Parameterized Query
    const query = `
        SELECT posts.*, users.username 
        FROM posts 
        JOIN users ON posts.user_id = users.id 
        WHERE posts.title LIKE ? OR posts.content LIKE ?
        ORDER BY posts.created_at DESC
    `;
    
    const searchPattern = `%${keyword}%`;
    
    db.all(query, [searchPattern, searchPattern], (err, posts) => {
        if (err) {
            console.error('Search error:', err);
            return res.status(500).json({ error: 'Search failed' });
        }
        res.json(posts);
    });
});
```

4. ทดสอบว่า SQL Injection payloads ไม่ทำงานแล้ว

---

### Task 6: แก้ XSS (30 นาที)

#### 📝 สิ่งที่ต้องทำ

1. **แก้ Stored XSS ใน Comments:**

แก้ในไฟล์ `public/post.html`:

```javascript
async function loadComments() {
    try {
        const response = await fetch(`/api/posts/${currentPostId}/comments`);
        const comments = await response.json();

        const commentsList = document.getElementById('commentsList');

        if (comments.length === 0) {
            commentsList.innerHTML = '<p>No comments yet. Be the first!</p>';
            return;
        }

        // ✅ SECURE: ใช้ escapeHtml() กับ comment content
        commentsList.innerHTML = comments.map(comment => `
            <div class="comment">
                <p class="comment-author">
                    <strong>${escapeHtml(comment.username)}</strong> - 
                    ${new Date(comment.created_at).toLocaleDateString('th-TH')}
                </p>
                <p class="comment-content">${escapeHtml(comment.content)}</p>
            </div>
        `).join('');
    } catch (error) {
        console.error('Error loading comments:', error);
    }
}
```

2. **แก้ Reflected XSS ใน Search:**

แก้ในไฟล์ `public/index.html`:

```javascript
async function searchPosts() {
    const keyword = document.getElementById('searchInput').value;
    const resultsDiv = document.getElementById('searchResults');
    
    if (!keyword.trim()) {
        resultsDiv.innerHTML = '';
        return;
    }

    try {
        // ✅ SECURE: ใช้ escapeHtml() กับ keyword
        resultsDiv.innerHTML = `<p>Searching for: <strong>"${escapeHtml(keyword)}"</strong></p>`;
        
        const response = await fetch(`/api/posts/search?q=${encodeURIComponent(keyword)}`);
        const posts = await response.json();
        
        if (posts.length === 0) {
            resultsDiv.innerHTML += '<p>No posts found</p>';
        } else {
            resultsDiv.innerHTML += `<p>Found ${posts.length} result(s)</p>`;
            displayPosts(posts);
        }
    } catch (error) {
        console.error('Search error:', error);
        resultsDiv.innerHTML = '<p class="error">Search failed</p>';
    }
}
```

3. **เพิ่ม Content Security Policy (Bonus)**

เพิ่มใน `server-secure.js`:

```javascript
// Security headers
app.use((req, res, next) => {
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    next();
});
```

4. ทดสอบว่า XSS payloads ไม่ทำงานแล้ว

---

## 📊 Part 6: การเขียน Report (30 นาที)

### รูปแบบ Report

จัดทำเอกสาร `lab7_report_[StudentID].pdf` ที่มีโครงสร้างดังนี้:

```markdown
# Lab 7 Report: Web Application Security
**Student ID:** [รหัสนักศึกษา]
**Name:** [ชื่อ-นามสกุล]
**Date:** [วันที่ทำ Lab]

---

## Executive Summary
[สรุปภาพรวมช่องโหว่ที่พบและผลกระทบ 3-4 ประโยค]

---

## 1. SQL Injection Vulnerabilities

### 1.1 Login Form Bypass

**Vulnerability Description:**
[อธิบายช่องโหว่]

**Vulnerable Code:**
```javascript
[วางโค้ดที่มีปัญหา]
```

**Exploitation:**
- **Payload Used:** `[payload ที่ใช้]`
- **Actual SQL Query:** `[query ที่ถูก execute จริง]`
- **Result:** [ผลที่ได้]

**Screenshot:**
[แนบภาพหน้าจอการทดสอบ]

**Secure Code:**
```javascript
[วางโค้ดที่แก้ไขแล้ว]
```

**Explanation:**
[อธิบายว่าแก้อย่างไร และทำไม]

---

### 1.2 Search Feature SQL Injection

[ทำแบบเดียวกับ 1.1]

---

## 2. Cross-Site Scripting (XSS) Vulnerabilities

### 2.1 Stored XSS in Comments

**Vulnerability Description:**
[อธิบาย]

**Vulnerable Code:**
```javascript
[โค้ดที่มีปัญหา]
```

**Exploitation:**
- **Payload Used:** `[payload]`
- **Impact:** [ผลกระทบ]

**Screenshot:**
[ภาพหน้าจอ]

**Secure Code:**
```javascript
[โค้ดแก้ไข]
```

---

### 2.2 Reflected XSS in Search

[ทำแบบเดียวกับ 2.1]

---

## 3. Security Best Practices Applied

### 3.1 Input Validation
- [อธิบายการ validate input]

### 3.2 Output Encoding
- [อธิบายการ encode output]

### 3.3 Parameterized Queries
- [อธิบายการใช้ prepared statements]

---

## 4. Testing Results

### Before Fix:
| Vulnerability | Exploitable? | Severity |
|---------------|--------------|----------|
| SQLi - Login | ✅ Yes | High |
| SQLi - Search | ✅ Yes | High |
| Stored XSS | ✅ Yes | High |
| Reflected XSS | ✅ Yes | Medium |

### After Fix:
| Vulnerability | Exploitable? | Verified? |
|---------------|--------------|-----------|
| SQLi - Login | ❌ No | ✅ Yes |
| SQLi - Search | ❌ No | ✅ Yes |
| Stored XSS | ❌ No | ✅ Yes |
| Reflected XSS | ❌ No | ✅ Yes |

---

## 5. Lessons Learned

1. [บทเรียนที่ได้เรียนรู้ข้อ 1]
2. [บทเรียนที่ได้เรียนรู้ข้อ 2]
3. [บทเรียนที่ได้เรียนรู้ข้อ 3]

---

## 6. Recommendations

1. **Code Review:**
   - [คำแนะนำ]

2. **Automated Testing:**
   - [คำแนะนำ]

3. **Security Training:**
   - [คำแนะนำ]

---

## Appendix: Testing Commands

[รวม payloads และคำสั่งที่ใช้ทดสอบ]
```

---

## 📏 เกณฑ์การให้คะแนน (10 คะแนน)

| หัวข้อ | คะแนน | รายละเอียด |
|--------|-------|------------|
| **Part 1: SQL Injection Testing** | 2 | ทดสอบและบันทึก SQL Injection ใน Login และ Search |
| **Part 2: XSS Testing** | 2 | ทดสอบและบันทึก Stored XSS และ Reflected XSS |
| **Part 3: Fixing SQL Injection** | 2 | แก้ไขช่องโหว่ SQL Injection ได้ถูกต้อง |
| **Part 4: Fixing XSS** | 2 | แก้ไขช่องโหว่ XSS ได้ถูกต้อง |
| **Part 5: Report Quality** | 1.5 | รายงานครบถ้วน มี screenshot, code comparison |
| **Part 6: Understanding & Recommendations** | 0.5 | แสดงความเข้าใจและให้คำแนะนำที่ดี |

---

## 🎁 Bonus Challenges (คะแนนพิเศษ)

### Bonus 1: Broken Access Control (2 คะแนน)

แก้ไข endpoint `/api/users/:id` และ `PUT /api/users/:id` ให้ตรวจสอบว่า:
- User สามารถดู profile ตัวเองได้เท่านั้น
- User สามารถแก้ไข profile ตัวเองได้เท่านั้น

### Bonus 2: Implement CSP (1 คะแนน)

เพิ่ม Content Security Policy headers ที่เหมาะสม

### Bonus 3: Password Hashing (2 คะแนน)

แก้ไขระบบให้เก็บ password แบบ hash (bcrypt) แทนการเก็บ plain text

---

## 📦 การส่งงาน

**ส่งไฟล์ทั้งหมดใน folder เดียว:**
```
lab7_[StudentID].zip
├── server.js (vulnerable version)
├── server-secure.js (fixed version)
├── package.json
├── database.js
├── public/ (all frontend files)
└── lab7_report_[StudentID].pdf
```

**วันที่ส่ง:** [กำหนดวันที่]

**วิธีส่ง:** [ระบุช่องทางการส่ง เช่น Google Classroom, Email, etc.]

---

## 🚀 Tips สำหรับนักศึกษา

1. **อย่ากลัวที่จะทำผิด** - นี่คือสภาพแวดล้อมการเรียนรู้
2. **ทดสอบทีละขั้นตอน** - อย่ารีบร้อน
3. **บันทึกทุกอย่าง** - screenshot, payloads, ผลลัพธ์
4. **เข้าใจ "ทำไม"** - ไม่ใช่แค่ "อย่างไร"
5. **ถามเมื่อสงสัย** - อาจารย์และเพื่อนพร้อมช่วย

---

## 📚 แหล่งข้อมูลเพิ่มเติม

- OWASP Top 10: https://owasp.org/Top10/
- SQL Injection Cheat Sheet: https://portswigger.net/web-security/sql-injection/cheat-sheet
- XSS Cheat Sheet: https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
- Node.js Security Best Practices: https://nodejs.org/en/docs/guides/security/

---

**หมายเหตุ:**
- System นี้ถูกสร้างขึ้นเพื่อการศึกษาเท่านั้น
- ห้ามนำเทคนิคที่เรียนรู้ไปใช้กับระบบจริงโดยไม่ได้รับอนุญาต
- การ hack ระบบโดยไม่ได้รับอนุญาตผิดกฎหมาย

---

**Good luck and happy hacking! 🎯**
