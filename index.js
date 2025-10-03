// تحميل المكتبات
require('dotenv').config();
const express = require('express');
const sql = require('mssql');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// إنشاء تطبيق
const app = express();
app.use(express.json());

// إعداد الاتصال
const dbConfig = {
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    server: process.env.DB_SERVER,
    database: process.env.DB_NAME,
    options: {
        encrypt: true,
        trustServerCertificate: true
    },
    pool: { max: 10, min: 0, idleTimeoutMillis: 30000 }
};

// ميدل وير لفحص التوكن
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.sendStatus(401);
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}
// test route for root
app.get('/', (req, res) => {
    res.send('✅ Rescue API is running');
});


// تسجيل مستخدم جديد
app.post('/register', async (req, res) => {
    const { username, email, password, role } = req.body;
    if (!username || !email || !password) {
        return res.status(400).json({ error: 'missing fields' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await sql.connect(dbConfig);

        const request = new sql.Request();
        request.input('UserName', sql.NVarChar(100), username);
        request.input('Email', sql.NVarChar(150), email);
        request.input('Role', sql.NVarChar(50), role || 'User');

        const result = await request.query(`
      INSERT INTO Users (UserName, Email, Role)
      OUTPUT INSERTED.UserID
      VALUES (@UserName, @Email, @Role)
    `);
        const userId = result.recordset[0].UserID;

        await new sql.Request()
            .input('UserID', sql.Int, userId)
            .input('Email', sql.NVarChar(150), email)
            .input('PasswordHash', sql.NVarChar(255), hashedPassword)
            .query(`
        INSERT INTO Login_Users (UserID, Email, PasswordHash)
        VALUES (@UserID, @Email, @PasswordHash)
      `);

        res.status(201).json({ ok: true, userId });
    } catch (err) {
        res.status(500).json({ error: err.message });
    } finally {
        sql.close();
    }
});

// تسجيل دخول
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'missing fields' });

    try {
        await sql.connect(dbConfig);
        const request = new sql.Request();
        request.input('Email', sql.NVarChar(150), email);

        const result = await request.query(`
      SELECT u.UserID, u.UserName, u.Role, l.PasswordHash
      FROM Users u
      JOIN Login_Users l ON u.UserID = l.UserID
      WHERE l.Email = @Email
    `);

        if (result.recordset.length === 0) return res.status(401).json({ error: 'invalid credentials' });

        const user = result.recordset[0];
        const match = await bcrypt.compare(password, user.PasswordHash);
        if (!match) return res.status(401).json({ error: 'invalid credentials' });

        const token = jwt.sign({ userId: user.UserID, role: user.Role }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (err) {
        res.status(500).json({ error: err.message });
    } finally {
        sql.close();
    }
});

// إضافة بلاغ (الحالة افتراضيًا جديد = 1)
app.post('/report', authenticateToken, async (req, res) => {
    const { unitId, locationWKT } = req.body;
    const userId = req.user.userId;
    if (!unitId || !locationWKT) return res.status(400).json({ error: 'missing fields' });

    try {
        await sql.connect(dbConfig);
        const request = new sql.Request();
        request.input('UserID', sql.Int, userId);
        request.input('UnitID', sql.Int, unitId);
        request.input('Report_StatusID', sql.Int, 1); // جديد
        request.input('LocationWKT', sql.NVarChar(100), locationWKT);

        await request.execute('AddReport');
        res.status(201).json({ ok: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    } finally {
        sql.close();
    }
});

// جلب كل البلاغات
app.get('/reports', async (req, res) => {
    try {
        await sql.connect(dbConfig);
        const result = await new sql.Request().execute('GetReports');
        res.json(result.recordset);
    } catch (err) {
        res.status(500).json({ error: err.message });
    } finally {
        sql.close();
    }
});

// جلب كل الوحدات
app.get('/units', async (req, res) => {
    try {
        await sql.connect(dbConfig);
        const result = await new sql.Request().execute('GetUnits');
        res.json(result.recordset);
    } catch (err) {
        res.status(500).json({ error: err.message });
    } finally {
        sql.close();
    }
});

// جلب كل الحالات
app.get('/statuses', authenticateToken, async (req, res) => {
    try {
        await sql.connect(dbConfig);
        const result = await new sql.Request().execute('GetStatuses');
        res.json(result.recordset);
    } catch (err) {
        res.status(500).json({ error: err.message });
    } finally {
        sql.close();
    }
});

// تحديث حالة البلاغ
app.put('/report/:id/status', async (req, res) => {
    const reportId = req.params.id;
    const { statusId } = req.body;
    if (!statusId) return res.status(400).json({ error: 'statusId required' });

    try {
        await sql.connect(dbConfig);
        const request = new sql.Request();
        request.input('ReportID', sql.Int, reportId);
        request.input('Report_StatusID', sql.Int, statusId);

        await request.query(`
      UPDATE Reports
      SET Report_StatusID = @Report_StatusID
      WHERE ReportID = @ReportID
    `);

        res.json({ ok: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    } finally {
        sql.close();
    }
});

// تشغيل السيرفر
const port = process.env.PORT || 3000;
app.listen(port, () => console.log('API running on port', port));
