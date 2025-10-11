// تحميل المكتبات
require('dotenv').config();
const express = require('express');
const sql = require('mssql');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const axios = require('axios');

// إنشاء التطبيق
const app = express();
app.use(express.json());
app.use(cors({
    origin: [
        "http://localhost:3000",
        "http://localhost:3001",
        "https://rescue-net-rho.vercel.app",
        "https://dashboard-rescu.netlify.app"
    ],
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true
}));

// إعداد الاتصال بقاعدة البيانات
const dbConfig = {
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    server: process.env.DB_SERVER,
    database: process.env.DB_NAME,
    options: { encrypt: true, trustServerCertificate: true },
    pool: { max: 10, min: 0, idleTimeoutMillis: 30000 }
};

// فحص التوكن
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

// اختبار السيرفر
app.get('/', (req, res) => {
    res.send(`
    <div style="font-family: Arial; text-align:center; margin-top:50px;">
      <h2 style="color:green;">🚀 Rescue API is Live 🚀</h2>
      <p>Developer: <b>Omar Ashraf</b> | Team: Geo-MASS</p>
    </div>
  `);
});

// تسجيل مستخدم جديد
app.post('/register', async (req, res) => {
    const { username, email, password, role } = req.body;
    if (!username || !email || !password)
        return res.status(400).json({ error: 'missing fields' });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await sql.connect(dbConfig);

        const result = await new sql.Request()
            .input('UserName', sql.NVarChar(100), username)
            .input('Email', sql.NVarChar(150), email)
            .input('Role', sql.NVarChar(50), role || 'User')
            .query(`
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

// تسجيل الدخول
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'missing fields' });

    try {
        await sql.connect(dbConfig);
        const result = await new sql.Request()
            .input('Email', sql.NVarChar(150), email)
            .query(`
        SELECT u.UserID, u.UserName, u.Role, l.PasswordHash
        FROM Users u
        JOIN Login_Users l ON u.UserID = l.UserID
        WHERE l.Email = @Email
      `);

        if (result.recordset.length === 0)
            return res.status(401).json({ error: 'invalid credentials' });

        const user = result.recordset[0];
        const match = await bcrypt.compare(password, user.PasswordHash);
        if (!match) return res.status(401).json({ error: 'invalid credentials' });

        const token = jwt.sign(
            { userId: user.UserID, role: user.Role },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.json({
            ok: true,
            token,
            userId: user.UserID,
            role: user.Role
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    } finally {
        sql.close();
    }
});

// إضافة بلاغ
app.post('/report', authenticateToken, async (req, res) => {
    const { unitId, locationWKT } = req.body;
    const userId = req.user.userId;

    if (!unitId || !locationWKT)
        return res.status(400).json({ error: 'missing fields' });

    try {
        await sql.connect(dbConfig);

        const request = new sql.Request();
        request.input('UserID', sql.Int, userId);
        request.input('UnitID', sql.Int, unitId);
        request.input('Report_StatusID', sql.Int, 1);
        request.input('LocationWKT', sql.NVarChar(200), locationWKT);

        await request.execute('AddReport');

        const reportIdQuery = await new sql.Request().query('SELECT TOP 1 ReportID FROM Reports ORDER BY ReportID DESC');
        const reportId = reportIdQuery.recordset[0].ReportID;

        res.status(201).json({
            ok: true,
            message: "report created successfully",
            reportId
        });
    } catch (err) {
        console.error("Report Error:", err.message);
        res.status(500).json({ error: err.message });
    } finally {
        sql.close();
    }
});

// جلب البلاغات
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

// جلب الوحدات
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

// جلب الحالات
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

// دالة تحليل WKT
function extractCoords(wkt) {
    if (!wkt) return null;
    wkt = wkt.replace(/POINT|\(|\)/gi, "").trim();
    const parts = wkt.split(" ");
    if (parts.length < 2) return null;
    return [parseFloat(parts[0]), parseFloat(parts[1])];
}

// دالة حساب المسارات
async function calculateRoutes() {
    try {
        await sql.connect(dbConfig);
        const reportsResult = await new sql.Request().query(`
      SELECT r.ReportID, r.Location.STAsText() AS ReportLocation
      FROM Reports r
      WHERE r.Report_StatusID = 1
      ORDER BY r.ReportID DESC
    `);

        if (reportsResult.recordset.length === 0) {
            console.log("لا توجد بلاغات جديدة");
            return;
        }

        const reports = reportsResult.recordset;
        const processedRoutes = [];

        for (const report of reports) {
            const reportCoords = extractCoords(report.ReportLocation);
            if (!reportCoords) continue;

            const routeCheck = await new sql.Request()
                .input("ReportID", sql.Int, report.ReportID)
                .query("SELECT RouteID FROM Routes WHERE ReportID = @ReportID");

            if (routeCheck.recordset.length > 0) continue;

            const unitsResult = await new sql.Request().query(`
        SELECT UnitID, UnitName, Location.STAsText() AS LocationWKT 
        FROM Units
      `);

            const units = unitsResult.recordset;
            let bestUnit = null;
            let bestDuration = Infinity;
            let bestDistance = Infinity;
            let bestRouteCoords = [];

            for (const unit of units) {
                const unitCoords = extractCoords(unit.LocationWKT);
                if (!unitCoords) continue;

                try {
                    const orsResponse = await axios.post(
                        "https://api.openrouteservice.org/v2/directions/driving-car/geojson",
                        { coordinates: [unitCoords, reportCoords] },
                        {
                            headers: {
                                Authorization: process.env.ORS_API_KEY,
                                "Content-Type": "application/json",
                            },
                        }
                    );

                    const data = orsResponse.data;
                    if (!data.features || !data.features.length) continue;

                    const summary = data.features[0].properties.summary;
                    const geometry = data.features[0].geometry;

                    const duration = summary.duration;
                    const distance = summary.distance;

                    if (duration < bestDuration) {
                        bestDuration = duration;
                        bestDistance = distance;
                        bestUnit = unit;
                        bestRouteCoords = geometry.coordinates;
                    }
                } catch (err) {
                    console.log("خطأ في ORS:", err.message);
                }
            }

            if (!bestUnit) continue;

            const routeInsert = await new sql.Request()
                .input("ReportID", sql.Int, report.ReportID)
                .input("UnitID", sql.Int, bestUnit.UnitID)
                .input("Distance", sql.Float, bestDistance)
                .input("Duration", sql.Float, bestDuration)
                .query(`
          INSERT INTO Routes (ReportID, UnitID, Distance, Duration, CreatedAt)
          OUTPUT INSERTED.RouteID
          VALUES (@ReportID, @UnitID, @Distance, @Duration, GETDATE())
        `);

            const routeID = routeInsert.recordset[0].RouteID;

            for (let i = 0; i < bestRouteCoords.length; i++) {
                const [lon, lat] = bestRouteCoords[i];
                await new sql.Request()
                    .input("RouteID", sql.Int, routeID)
                    .input("SequenceNo", sql.Int, i + 1)
                    .input("Latitude", sql.Float, lat)
                    .input("Longitude", sql.Float, lon)
                    .query(`
            INSERT INTO RoutePoints (RouteID, SequenceNo, Latitude, Longitude)
            VALUES (@RouteID, @SequenceNo, @Latitude, @Longitude)
          `);
            }

            processedRoutes.push({
                reportId: report.ReportID,
                routeId: routeID,
                unit: bestUnit.UnitName,
            });
        }

        if (processedRoutes.length > 0)
            console.log("تم إنشاء مسارات جديدة:", processedRoutes);

    } catch (err) {
        console.error("خطأ أثناء التنفيذ:", err);
    } finally {
        sql.close();
    }
}
// نقطة نهاية لجلب نقاط المسار بناءً على RouteID
// ✅ نقطة نهاية لجلب RouteID بناءً على ReportID
app.get("/routes/by-report/:reportId", async (req, res) => {
    const { reportId } = req.params;

    try {
        await sql.connect(dbConfig);

        const routeResult = await new sql.Request()
            .input("ReportID", sql.Int, reportId)
            .query(`
        SELECT TOP 1 RouteID 
        FROM Routes 
        WHERE ReportID = @ReportID
      `);

        if (routeResult.recordset.length === 0) {
            return res.status(404).json({
                ok: false,
                message: "لم يتم العثور على مسار مرتبط بهذا البلاغ",
            });
        }

        const routeId = routeResult.recordset[0].RouteID;
        res.json({ ok: true, routeId });
    } catch (err) {
        console.error("Database error:", err);
        res.status(500).json({ ok: false, error: err.message });
    } finally {
        sql.close();
    }
});


// ✅ نقطة نهاية لجلب نقاط المسار بناءً على RouteID
app.get("/route-points/:routeId", async (req, res) => {
    const { routeId } = req.params;

    try {
        await sql.connect(dbConfig);

        const pointsResult = await new sql.Request()
            .input("RouteID", sql.Int, routeId)
            .query(`
        SELECT Latitude AS lat, Longitude AS lng, SequenceNo
        FROM RoutePoints
        WHERE RouteID = @RouteID
        ORDER BY SequenceNo ASC
      `);

        if (pointsResult.recordset.length === 0) {
            return res.status(404).json({
                ok: false,
                message: "لم يتم العثور على نقاط المسار",
            });
        }

        res.json({
            ok: true,
            routeId,
            points: pointsResult.recordset,
        });
    } catch (err) {
        console.error("Database error:", err);
        res.status(500).json({ ok: false, error: err.message });
    } finally {
        sql.close();
    }
});
// ✅ نقطة نهاية لتحديث المسارات يدويًا بعد البلاغ
app.post("/run-calculate-routes", async (req, res) => {
    try {
        await calculateRoutes();
        res.json({ ok: true, message: "Routes recalculated successfully" });
    } catch (err) {
        console.error("Error recalculating routes:", err);
        res.status(500).json({ ok: false, error: err.message });
    }
});
// استدعاء الدالة كل 5 ثواني
// setInterval(calculateRoutes, 5000);
// تشغيل السيرفر
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`
  ============================================
     🚀 Rescue API is running on port ${port} 🚀
     👨‍💻 Developer: Omar, Sanaa, Maysa (Backend Dev)
     🌍 Team: Geo-MASS
     ✅ Status: All systems operational
  ============================================
  `));
