require('dotenv').config(); // 환경 변수 로드
const express = require('express');
const session = require('express-session');
const mysql = require('mysql2');
const MySQLStore = require('express-mysql-session')(session);
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3001;

// 1. DB 연결 설정 (Connection Pool 사용)
const dbOptions = {
    host: process.env.DB_HOST,
    port: process.env.DB_PORT,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    connectionLimit: 10 // 동시 접속 수 제한
};

const db = mysql.createPool(dbOptions);

// DB 연결 테스트
db.getConnection((err, connection) => {
    if (err) {
        console.error('❌ Database connection failed:', err.code);
        console.error('Check your .env file and ensure MySQL is running.');
    } else {
        console.log('✅ Connected to MySQL Database');
        connection.release();
    }
});

// 2. 세션 스토어 설정 (MySQL에 세션 저장)
const sessionStore = new MySQLStore(dbOptions);

// 3. 미들웨어 설정
app.use(cors({
    origin: process.env.FRONTEND_URL, // 환경 변수에서 가져옴
    credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
    key: 'session_cookie_name',
    secret: process.env.SESSION_SECRET, // 환경 변수에서 가져옴
    store: sessionStore, // 세션을 MySQL에 저장
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false, // https 적용 시 true로 변경 필요
        maxAge: process.env.SESSION_TIME
    }
}));

// 4. 테이블 초기화 (서버 시작 시 자동 생성)
const initTables = () => {
    const tables = [
        // 회원 테이블
        `CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL
        )`,
        // 익명 게시판
        `CREATE TABLE IF NOT EXISTS anonymous_posts (
            id INT AUTO_INCREMENT PRIMARY KEY,
            title VARCHAR(255) NOT NULL,
            content TEXT NOT NULL,
            author VARCHAR(255),
            views INT DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INT
        )`,
        // 공지사항 (중요 공지 포함)
        `CREATE TABLE IF NOT EXISTS notice_posts (
            id INT AUTO_INCREMENT PRIMARY KEY,
            title VARCHAR(255) NOT NULL,
            content TEXT NOT NULL,
            author VARCHAR(255),
            views INT DEFAULT 0,
            is_important BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INT
        )`,
        // 과 게시판 (학과 포함)
        `CREATE TABLE IF NOT EXISTS department_posts (
            id INT AUTO_INCREMENT PRIMARY KEY,
            title VARCHAR(255) NOT NULL,
            content TEXT NOT NULL,
            author VARCHAR(255),
            department VARCHAR(255),
            views INT DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INT
        )`
    ];

    tables.forEach(sql => {
        db.query(sql, (err) => {
            if (err) console.error('Table creation error:', err);
        });
    });
};

// DB 연결 성공 시 테이블 생성 시도
initTables();


// 5. API 라우트 구현

// --- 인증 (Auth) ---
app.get('/api/auth/check', (req, res) => {
    if (req.session.user) {
        res.json({ isAuthenticated: true, user: req.session.user });
    } else {
        res.json({ isAuthenticated: false });
    }
});

app.post('/api/auth/register', (req, res) => {
    const { username, password } = req.body;
    const sql = 'INSERT INTO users (username, password) VALUES (?, ?)';
    db.query(sql, [username, password], (err, result) => {
        if (err) {
            if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: '이미 존재하는 아이디입니다.' });
            return res.status(500).json({ error: err.message });
        }
        const user = { id: result.insertId, username };
        req.session.user = user;
        req.session.save(() => res.json({ message: '회원가입 성공', user }));
    });
});

app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    const sql = 'SELECT * FROM users WHERE username = ? AND password = ?';
    db.query(sql, [username, password], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        if (results.length === 0) return res.status(401).json({ error: '아이디 또는 비밀번호 오류' });

        const user = results[0];
        req.session.user = { id: user.id, username: user.username };
        req.session.save(() => res.json({ message: '로그인 성공', user: req.session.user }));
    });
});

app.post('/api/auth/logout', (req, res) => {
    req.session.destroy(() => {
        res.clearCookie('session_cookie_name');
        res.json({ message: '로그아웃 성공' });
    });
});

// --- 게시판 (Board) ---
const getTableName = (boardName) => {
    if (boardName === 'anonymous') return 'anonymous_posts';
    if (boardName === 'notice') return 'notice_posts';
    if (boardName === 'department') return 'department_posts';
    return null;
};

app.get('/api/:boardName', (req, res) => {
    const table = getTableName(req.params.boardName);
    if (!table) return res.status(404).json({ error: '존재하지 않는 게시판' });

    const sql = `SELECT * FROM ${table} ORDER BY created_at DESC`;
    db.query(sql, (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

app.get('/api/:boardName/:id', (req, res) => {
    const table = getTableName(req.params.boardName);
    const id = req.params.id;

    // 조회수 증가
    db.query(`UPDATE ${table} SET views = views + 1 WHERE id = ?`, [id]);

    db.query(`SELECT * FROM ${table} WHERE id = ?`, [id], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        if (results.length === 0) return res.status(404).json({ error: '게시글 없음' });
        res.json(results[0]);
    });
});

app.post('/api/:boardName', (req, res) => {
    if (!req.session.user) return res.status(401).json({ needLogin: true });

    const table = getTableName(req.params.boardName);
    const { title, content, author, is_important, department } = req.body;
    const userId = req.session.user.id;
    const username = req.session.user.username;

    let sql = `INSERT INTO ${table} (title, content, author, user_id) VALUES (?, ?, ?, ?)`;
    let params = [title, content, author, userId];

    if (table === 'notice_posts') {
        sql = `INSERT INTO ${table} (title, content, author, user_id, is_important) VALUES (?, ?, ?, ?, ?)`;
        // 공지사항은 로그인한 유저명(username)을 작성자로 강제 설정
        params = [title, content, username, userId, is_important ? 1 : 0];
    } else if (table === 'department_posts') {
        sql = `INSERT INTO ${table} (title, content, author, department, user_id) VALUES (?, ?, ?, ?, ?)`;
        params = [title, content, author, department, userId];
    }

    db.query(sql, params, (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: '작성 성공', id: result.insertId });
    });
});

app.delete('/api/:boardName/:id', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: '로그인 필요' });

    const table = getTableName(req.params.boardName);
    const id = req.params.id;
    const userId = req.session.user.id;

    db.query(`SELECT user_id FROM ${table} WHERE id = ?`, [id], (err, results) => {
        if (results.length === 0) return res.status(404).json({ error: '게시글 없음' });
        if (results[0].user_id !== userId) return res.status(403).json({ error: '본인 글만 삭제 가능' });

        db.query(`DELETE FROM ${table} WHERE id = ?`, [id], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: '삭제 성공' });
        });
    });
});

app.listen(PORT, () => {
    console.log(`🚀 MySQL Backend running on port ${PORT}`);
});