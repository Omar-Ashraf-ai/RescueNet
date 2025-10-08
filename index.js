// تحميل المكتبات
require('dotenv').config();
const express = require('express');
const sql = require('mssql');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');

// إنشاء تطبيق
const app = express();
app.use(express.json());
app.use(cors({
    origin: [
        "http://localhost:3000",    // React أثناء التجربة
        "http://localhost:3001",    // في حالة آلاء فاتحة المشروع على بورت تاني
        "https://rescue-net-rho.vercel.app",  // واجهة Flutter
        "https://dashboard-rescu.netlify.app" // الداشبورد لما تترفع
    ],
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true
}));
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
    res.send(`
    <div style="font-family: Arial, sans-serif; text-align:center; margin-top:50px;">
      <h1 style="color:green;">🚀 Rescue API is Live 🚀</h1>
      <p>👨‍💻 Developed by <b>Omar Ashraf</b> (Backend Developer)</p>
      <p>🌍 With the support of <b>Geo-Mass Team</b></p>
      <p>✅ Everything is running smoothly</p>
    </div>
  `);
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
// جلب النقاط الخاصة بالمسار (Route Points)
app.get("/api/route-points/:routeID", async (req, res) => {
    const routeID = req.params.routeID;
    try {
        await sql.connect(dbConfig);
        const result = await new sql.Request()
            .input("routeID", sql.Int, routeID)
            .query(`
        SELECT SequenceNo, Latitude, Longitude 
        FROM RoutePoints 
        WHERE RouteID = @routeID 
        ORDER BY SequenceNo
      `);

        res.json(result.recordset);
    } catch (err) {
        console.error("Database error:", err);
        res.status(500).send("Database error");
    } finally {
        sql.close();
    }
});
// حساب أقرب وحدة وتنفيذ مسار جديد
const axios = require('axios');
app.post('/api/calculate-route', async (req, res) => {
    try {
        await sql.connect(dbConfig);

        const reportResult = await new sql.Request().query(`
      SELECT TOP 1 
        r.ReportID,
        r.Location.STAsText() AS ReportLocation
      FROM Reports r
      WHERE r.Report_StatusID = 1
      ORDER BY r.ReportID DESC
    `);

        if (reportResult.recordset.length === 0)
            return res.status(404).json({ error: "لا يوجد بلاغ جديد" });

        const report = reportResult.recordset[0];
        const reportCoords = extractCoords(report.ReportLocation);
        if (!reportCoords) return res.status(400).json({ error: "فشل في قراءة موقع البلاغ" });

        const unitsResult = await new sql.Request().query(`
      SELECT UnitID, UnitName, Location.STAsText() AS LocationWKT FROM Units
    `);
        const units = unitsResult.recordset;

        let bestUnit = null;
        let bestDuration = Infinity;
        let bestDistance = Infinity;

        for (const unit of units) {
            const unitCoords = extractCoords(unit.LocationWKT);
            if (!unitCoords) continue;

            try {
                const orsResponse = await axios.post(
                    "https://api.openrouteservice.org/v2/directions/driving-car/geojson",
                    { coordinates: [reportCoords, unitCoords] },
                    {
                        headers: {
                            Authorization: process.env.ORS_API_KEY,
                            "Content-Type": "application/json"
                        }
                    }
                );

                const data = orsResponse.data;
                if (!data.features || !data.features.length) continue;

                const summary = data.features[0].properties.summary;
                const duration = summary.duration;
                const distance = summary.distance;

                if (duration < bestDuration) {
                    bestDuration = duration;
                    bestDistance = distance;
                    bestUnit = unit;
                }
            } catch (error) {
                console.log("⚠ فشل في حساب المسار:", error.response?.status || error.message);
            }
        }

        if (bestUnit) {
            await new sql.Request()
                .input("ReportID", sql.Int, report.ReportID)
                .input("UnitID", sql.Int, bestUnit.UnitID)
                .input("Distance", sql.Float, bestDistance)
                .input("Duration", sql.Float, bestDuration)
                .query(`
          INSERT INTO Routes (ReportID, UnitID, Distance, Duration, CreatedAt)
          VALUES (@ReportID, @UnitID, @Distance, @Duration, GETDATE())
        `);
            // استخراج RouteID الذي تم إنشاؤه للتو
            const routeIDResult = await new sql.Request().query(`
  SELECT TOP 1 RouteID FROM Routes ORDER BY RouteID DESC
`);
            const routeID = routeIDResult.recordset[0].RouteID;

            // حفظ النقاط في جدول RoutePoints
            const coordinates = response.data.features[0].geometry.coordinates;

            for (let i = 0; i < coordinates.length; i++) {
                const [lon, lat] = coordinates[i];
                await new sql.Request()
                    .input("RouteID", sql.Int, routeID)
                    .input("SequenceNo", sql.Int, i + 1)
                    .input("Latitude", sql.Float, lat)
                    .input("Longitude", sql.Float, lon)
                    .input("Passed", sql.Bit, 0)
                    .query(`
      INSERT INTO RoutePoints (RouteID, SequenceNo, Latitude, Longitude, Passed)
      VALUES (@RouteID, @SequenceNo, @Latitude, @Longitude, @Passed)
    `);
            }

            // تخزين الشكل المكاني في RouteGeom
            const geojson = JSON.stringify(response.data.features[0].geometry);
            await new sql.Request()
                .input("RouteID", sql.Int, routeID)
                .input("RouteGeom", sql.NVarChar(sql.MAX), geojson)
                .query(`
    UPDATE Routes SET RouteGeom = @RouteGeom WHERE RouteID = @RouteID
  `);

            res.json({
                ok: true,
                message: "تم تحديد أقرب وحدة بنجاح",
                unit: bestUnit.UnitName,
                durationMinutes: (bestDuration / 60).toFixed(2),
                distanceKm: (bestDistance / 1000).toFixed(2)
            });
        } else {
            res.status(404).json({ error: "لم يتم العثور على مسار مناسب" });
        }
    } catch (err) {
        console.error("❌ خطأ أثناء التنفيذ:", err);
        res.status(500).json({ error: err.message });
    } finally {
        sql.close();
    }
});

// دالة لتحويل WKT إلى إحداثيات
function extractCoords(wkt) {
    if (!wkt) return null;
    wkt = wkt.replace(/POINT|\(|\)/gi, "").trim();
    const parts = wkt.split(" ");
    if (parts.length < 2) return null;
    return [parseFloat(parts[0]), parseFloat(parts[1])];
}
// تشغيل السيرفر
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`
  ============================================
     🚀 Rescue API is running on port ${port} 🚀
     👨‍💻 Developer: Omar Ashraf (Backend Dev)
     🌍 Team: Geo-MASS
     ✅ Status: All systems operational
  ============================================
  `));
