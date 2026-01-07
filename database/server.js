const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const multer = require('multer');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const upload = multer();

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

const SECRET = 'super_secret_key'; // ⚠️ change in production

// -------------------- DATABASE -------------------- //
const db = new sqlite3.Database('./social.db', err => {
  if (err) console.error('DB error:', err);
  else console.log('Connected to SQLite database');
});

db.run('PRAGMA foreign_keys = ON');

// -------------------- TABLES -------------------- //
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      uid INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      display_name TEXT,
      about TEXT,
      picture BLOB
    );
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS sessions (
      sid INTEGER PRIMARY KEY AUTOINCREMENT,
      uid INTEGER NOT NULL,
      token TEXT NOT NULL,
      FOREIGN KEY(uid) REFERENCES users(uid) ON DELETE CASCADE
    );
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS posts (
      pid INTEGER PRIMARY KEY AUTOINCREMENT,
      uid INTEGER NOT NULL,
      image BLOB NOT NULL,
      description TEXT,
      FOREIGN KEY(uid) REFERENCES users(uid) ON DELETE CASCADE
    );
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS comments (
      cid INTEGER PRIMARY KEY AUTOINCREMENT,
      pid INTEGER NOT NULL,
      uid INTEGER NOT NULL,
      text TEXT NOT NULL,
      FOREIGN KEY(pid) REFERENCES posts(pid) ON DELETE CASCADE,
      FOREIGN KEY(uid) REFERENCES users(uid) ON DELETE CASCADE
    );
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS post_likes (
      plid INTEGER PRIMARY KEY AUTOINCREMENT,
      pid INTEGER NOT NULL,
      uid INTEGER NOT NULL,
      FOREIGN KEY(pid) REFERENCES posts(pid) ON DELETE CASCADE,
      FOREIGN KEY(uid) REFERENCES users(uid) ON DELETE CASCADE
    );
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS comment_likes (
      clid INTEGER PRIMARY KEY AUTOINCREMENT,
      cid INTEGER NOT NULL,
      uid INTEGER NOT NULL,
      FOREIGN KEY(cid) REFERENCES comments(cid) ON DELETE CASCADE,
      FOREIGN KEY(uid) REFERENCES users(uid) ON DELETE CASCADE
    );
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS follows (
      fid INTEGER PRIMARY KEY AUTOINCREMENT,
      follower_id INTEGER NOT NULL,
      followed_id INTEGER NOT NULL,
      FOREIGN KEY(follower_id) REFERENCES users(uid) ON DELETE CASCADE,
      FOREIGN KEY(followed_id) REFERENCES users(uid) ON DELETE CASCADE
    );
  `);
});

// -------------------- AUTH HELPERS -------------------- //
function verifyToken(req, res, next) {
  const header = req.headers['authorization'];
  const token = header && header.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Missing token' });

  jwt.verify(token, SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });

    db.get(`SELECT * FROM sessions WHERE token = ?`, [token], (err, session) => {
      if (err) return res.status(500).json({ error: 'DB error' });
      if (!session) return res.status(403).json({ error: 'Session expired' });

      req.user = { uid: decoded.uid };
      next();
    });
  });
}

// -------------------- AUTH ROUTES -------------------- //
app.post('/register', async (req, res) => {
  const { username, password, display_name, about } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Missing username or password' });

  const hashed = await bcrypt.hash(password, 10);
  db.run(
    'INSERT INTO users (username, password, display_name, about) VALUES (?, ?, ?, ?)',
    [username, hashed, display_name, about],
    function (err) {
      if (err) return res.status(400).json({ error: 'Username already exists' });
      res.json({ uid: this.lastID });
    }
  );
});

app.post('/login', (req, res) => {
    console.log("loginliyooo")
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    valid = await bcrypt.compare(password, user.password);
    //valid = (password === user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ uid: user.uid }, SECRET, { expiresIn: '2h' });

    db.run(`INSERT INTO sessions (uid, token) VALUES (?, ?)`, [user.uid, token], (err) => {
      if (err) return res.status(500).json({ error: 'DB error' });
      res.json({ token });
    });
  });
});

app.post('/logout', verifyToken, (req, res) => {
  const header = req.headers['authorization'];
  const token = header.split(' ')[1];
  db.run(`DELETE FROM sessions WHERE token = ?`, [token], (err) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json({ success: true });
  });
});

// -------------------- PROTECTED ROUTES -------------------- //

// -------- USERS -------- //
app.get('/users/:uid', verifyToken, (req, res) => {
  getUserById(req.params.uid, res);
});

app.get('/users/', verifyToken, (req, res) => {
  getUserById(req.user.uid, res);
});

const getUserById = (uid, res) => {
  // 1. Get the User and Counts (db.get returns a single object, not an array)
  db.get(
    `SELECT 
       u.uid, u.username, u.display_name, u.about, u.picture,
       (SELECT COUNT(*) FROM follows WHERE followed_id = u.uid) AS follower_count,
       (SELECT COUNT(*) FROM follows WHERE follower_id = u.uid) AS following_count,
       (SELECT COUNT(*) FROM posts WHERE uid = u.uid) AS post_count
     FROM users u
     WHERE u.uid = ?`,
    [uid],
    (err, user) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!user) return res.status(404).json({ error: 'User not found' });

      // 2. Get the Posts for this user
      db.all(
        `SELECT pid, image, description FROM posts WHERE uid = ? ORDER BY pid DESC`,
        [uid],
        (err, posts) => {
          if (err) return res.status(500).json({ error: err.message });

          // Structure the final JSON
          const userProfile = {
            uid: user.uid,
            username: user.username,
            display_name: user.display_name,
            about: user.about,
            picture: user.picture,
            stats: {
              followers: user.follower_count,
              following: user.following_count,
              posts: user.post_count
            }
          };

          res.json({ user: userProfile, posts });
        }
      );
    }
  );
};

app.put('/users/picture', verifyToken, upload.single('picture'), (req, res) => {
  const uid = req.user.uid;
  
  // Check if a file was actually uploaded
  const picture = req.file ? req.file.buffer : null;

  if (!picture) {
    return res.status(400).json({ error: 'No image file provided' });
  }

  // Update the database
  db.run('UPDATE users SET picture = ? WHERE uid = ?', [picture, uid], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    
    // Return success message
    res.json({ 
      success: true, 
      message: 'Profile picture updated successfully' 
    });
  });
});

app.put('/users/display', verifyToken, (req, res) => {
  const uid = req.user.uid;
  const { displayName } = req.body;

  if (!displayName || displayName.trim() === '') {
    return res.status(400).json({ error: 'Display name cannot be empty' });
  }

  db.run('UPDATE users SET display_name = ? WHERE uid = ?', [displayName, uid], function(err) {
    if (err) return res.status(500).json({ error: err.message });

    res.json({
      success: true,
      message: 'Display name updated successfully'
    });
  });
});

app.put('/users/bio', verifyToken, (req, res) => {
  const uid = req.user.uid;
  const { bio } = req.body;

  if (!bio || bio.trim() === '') {
    return res.status(400).json({ error: 'Bio cannot be empty' });
  }

  db.run('UPDATE users SET about = ? WHERE uid = ?', [bio, uid], function(err) {
    if (err) return res.status(500).json({ error: err.message });

    res.json({
      success: true,
      message: 'About section updated successfully'
    });
  });
});






// -------- POSTS -------- //
app.get('/posts/:pid', verifyToken, (req, res) => {
  const pid = req.params.pid;
  db.get(
    `SELECT 
       p.pid, p.image, p.description,
       u.uid AS creator_id, u.username AS creator_username,
       u.display_name AS creator_display_name, u.picture AS creator_picture,
       (SELECT COUNT(*) FROM post_likes WHERE pid=p.pid) AS post_like_count
     FROM posts p
     JOIN users u ON p.uid = u.uid
     WHERE p.pid = ?`,
    [pid],
    (err, post) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!post) return res.status(404).json({ error: 'Post not found' });

      db.all(
        `SELECT 
           c.cid, c.text, c.uid AS commenter_id,
           u.display_name AS commenter_display_name,
           u.picture AS commenter_picture,
           (SELECT COUNT(*) FROM comment_likes WHERE cid=c.cid) AS comment_like_count
         FROM comments c
         JOIN users u ON c.uid = u.uid
         WHERE c.pid = ?
         ORDER BY c.cid ASC`,
        [pid],
        (err2, comments) => {
          if (err2) return res.status(500).json({ error: err2.message });
          res.json({ post, comments });
        }
      );
    }
  );
});

// Check if user liked a post
app.get('/posts/:pid/liked', verifyToken, (req, res) => {
  const uid = req.user.uid; // extracted from token
  const pid = req.params.pid;

  db.get(
    'SELECT 1 FROM post_likes WHERE pid = ? AND uid = ?',
    [pid, uid],
    (err, row) => {
      if (err) return res.status(500).json({ error: err.message });

      if (row) {
        // User has liked the post
        return res.sendStatus(200);
      } else {
        // User has NOT liked the post
        return res.sendStatus(400);
      }
    }
  );
});

app.post('/posts/:pid/liked', verifyToken, (req, res) => {
  const uid = req.user.uid;
  const pid = req.params.pid;

  // First, check if the like already exists
  db.get(
    'SELECT * FROM post_likes WHERE pid = ? AND uid = ?',
    [pid, uid],
    (err, row) => {
      if (err) return res.status(500).json({ error: err.message });

      if (row) {
        // User has already liked so unlike (delete)
        db.run(
          'DELETE FROM post_likes WHERE pid = ? AND uid = ?',
          [pid, uid],
          function (err2) {
            if (err2) return res.status(500).json({ error: err2.message });
            return res.status(201).json({ message: 'Post unliked' });
          }
        );
      } else {
        // User has not liked so add like (insert)
        db.run(
          'INSERT INTO post_likes (pid, uid) VALUES (?, ?)',
          [pid, uid],
          function (err2) {
            if (err2) return res.status(500).json({ error: err2.message });
            return res.status(200).json({ message: 'Post liked', plid: this.lastID });
          }
        );
      }
    }
  );
});


const sharp = require('sharp');

app.post('/posts', verifyToken, upload.single('image'), async (req, res) => {
  const uid = req.user.uid;
  const { description } = req.body;
  let image = req.file ? req.file.buffer : null;
  // compress the image here
  if (image) {
    image = await sharp(image)
      .resize({ width: 640, height: 640 })
      .jpeg({ quality: 70 })
      .toBuffer();
  }
  if (!image) return res.status(400).json({ error: 'Missing image' });

  db.run('INSERT INTO posts (uid, image, description) VALUES (?, ?, ?)', [uid, image, description], function(err){
    if (err) return res.status(500).json({ error: err.message });
    res.json({ pid: this.lastID });
  });
});

app.delete('/posts/:pid', verifyToken, (req, res) => {
  const uid = req.user.uid;
  db.run('DELETE FROM posts WHERE pid = ? AND uid = ?', [req.params.pid, uid], function(err){
    if(err) return res.status(500).json({error: err.message});
    res.json({ deleted: this.changes });
  });
});

// Check if user liked a post
app.get('/posts/:pid/liked', verifyToken, (req, res) => {
  const uid = req.user.uid; // extracted from token
  const pid = req.params.pid;

  db.get(
    'SELECT 1 FROM post_likes WHERE pid = ? AND uid = ?',
    [pid, uid],
    (err, row) => {
      if (err) return res.status(500).json({ error: err.message });

      if (row) {
        // User has liked the post
        return res.sendStatus(200);
      } else {
        // User has NOT liked the post
        return res.sendStatus(400);
      }
    }
  );
});

// -------- COMMENTS -------- //
app.post('/comments', verifyToken, (req,res)=>{
  const uid = req.user.uid;
  const { pid, text } = req.body;
  db.run('INSERT INTO comments (pid, uid, text) VALUES (?,?,?)', [pid, uid, text], function(err){
    if(err) return res.status(500).json({error: err.message});
    res.json({ cid: this.lastID });
  });
});

app.delete('/comments/:cid', verifyToken, (req,res)=>{
  const uid = req.user.uid;
  db.run('DELETE FROM comments WHERE cid=? AND uid=?', [req.params.cid, uid], function(err){
    if(err) return res.status(500).json({error: err.message});
    res.json({ deleted: this.changes });
  });
});

// -------- LIKES -------- //
app.post('/post_likes', verifyToken, (req,res)=>{
  const uid = req.user.uid;
  const { pid } = req.body;
  db.run(`INSERT INTO post_likes (pid, uid) 
          SELECT ?, ? WHERE NOT EXISTS (SELECT 1 FROM post_likes WHERE pid=? AND uid=?)`,
          [pid, uid, pid, uid], function(err){
            if(err) return res.status(500).json({error: err.message});
            res.json({ plid: this.lastID });
          });
});

app.delete('/post_likes', verifyToken, (req,res)=>{
  const uid = req.user.uid;
  const { pid } = req.body;
  db.run('DELETE FROM post_likes WHERE pid=? AND uid=?', [pid, uid], function(err){
    if(err) return res.status(500).json({error: err.message});
    res.json({ deleted: this.changes });
  });
});

app.post('/comment_likes', verifyToken, (req,res)=>{
  const uid = req.user.uid;
  const { cid } = req.body;
  db.run(`INSERT INTO comment_likes (cid, uid) 
          SELECT ?, ? WHERE NOT EXISTS (SELECT 1 FROM comment_likes WHERE cid=? AND uid=?)`,
          [cid, uid, cid, uid], function(err){
            if(err) return res.status(500).json({error: err.message});
            res.json({ clid: this.lastID });
          });
});

app.delete('/comment_likes', verifyToken, (req,res)=>{
  const uid = req.user.uid;
  const { cid } = req.body;
  db.run('DELETE FROM comment_likes WHERE cid=? AND uid=?', [cid, uid], function(err){
    if(err) return res.status(500).json({error: err.message});
    res.json({ deleted: this.changes });
  });
});

// -------- FOLLOWS -------- //
app.get('/follows/:followed_id', verifyToken, (req,res)=>{
  const follower_id = req.user.uid;
  const followed_id = req.params.followed_id;

  db.get('SELECT 1 FROM follows WHERE follower_id=? AND followed_id=?', [follower_id, followed_id], (err,row)=>{
    if(err) return res.status(500).json({error: err.message});
    if(row) return res.sendStatus(200);
    else return res.sendStatus(201);

  });
});

app.post('/follows', verifyToken, (req,res)=>{
  const follower_id = req.user.uid;
  const { followed_id } = req.body;
  db.run(`INSERT INTO follows (follower_id, followed_id)
          SELECT ?, ? WHERE NOT EXISTS (SELECT 1 FROM follows WHERE follower_id=? AND followed_id=?)`,
          [follower_id, followed_id, follower_id, followed_id], function(err){
            if(err) return res.status(500).json({error: err.message});
            res.json({ fid: this.lastID });
          });
});

app.delete('/follows', verifyToken, (req,res)=>{
  const follower_id = req.user.uid;
  const { followed_id } = req.body;
  db.run('DELETE FROM follows WHERE follower_id=? AND followed_id=?', [follower_id, followed_id], function(err){
    if(err) return res.status(500).json({error: err.message});
    res.json({ deleted: this.changes });
  });
});


// -------- FEED -------- //
app.get('/feed', verifyToken, (req,res)=>{
  const uid = req.user.uid;
  const limit = parseInt(req.query.limit) || 10;
  const offset = parseInt(req.query.offset) || 0;

  db.all(
    `SELECT 
       p.pid
     FROM posts p
     JOIN users u ON p.uid = u.uid
     WHERE p.uid IN (SELECT followed_id FROM follows WHERE follower_id=?)
     ORDER BY p.pid DESC
     LIMIT ? OFFSET ?`,
    [uid, limit, offset],
    (err, rows)=>{
      if(err) return res.status(500).json({error: err.message});
      res.json({ feed: rows });
    }
  );
});

// -------------------- SEACH -------------------- //

app.get('/search/users', verifyToken, (req, res) => {
  const q = req.query.q?.trim();

  if (!q) return res.status(400).json({ error: 'Missing search query' });

  const search = `%${q}%`;

  db.all(
    `SELECT uid, username, display_name, picture
     FROM users
     WHERE username LIKE ?
        OR display_name LIKE ?
        OR about LIKE ?
     LIMIT 30`,
    [search, search, search],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ users: rows });
    }
  );
});


// -------------------- START SERVER -------------------- //
const PORT = 3000;
app.listen(PORT, ()=> console.log(`Server running on port ${PORT}`));
