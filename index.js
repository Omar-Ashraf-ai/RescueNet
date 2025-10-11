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
app.use(cors({                              // بعرف صلاحيات الكروس عشان الرياكت يقدر يتصل بي
    origin: [
        "http://localhost:3000",    // React أثناء التجربة
        "http://localhost:3001",    // في حالة آلاء فاتحة المشروع على بورت تاني
        "https://rescue-net-rho.vercel.app",  // الرابط النهائي للموقع
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
//  بداية كود سناء الروتينج 
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
const axios = require("axios");
// دالة لتحليل WKT
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

      // تحقق إن البلاغ ملوش مسار محفوظ
      const routeCheck = await new sql.Request()
        .input("ReportID", sql.Int, report.ReportID)
        .query("SELECT RouteID FROM Routes WHERE ReportID = @ReportID");

      if (routeCheck.recordset.length > 0) {
        console.log(`م تخطي البلاغ ${report.ReportID} (المسار موجود مسبقًا)`);
        continue;
      }

      // كل الوحدات
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

      // حفظ المسار
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

      // حفظ النقاط في RoutePoints
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
        distanceKm: (bestDistance / 1000).toFixed(2),
        durationMin: (bestDuration / 60).toFixed(2),
      });

      console.log(`م حفظ مسار لبلاغ ${report.ReportID} (${bestUnit.UnitName})`);
    }

    if (processedRoutes.length === 0) {
      console.log("لم يتم توليد أي مسارات جديدة");
      return;
    }

    console.log("تم إنشاء المسارات التالية:");
    processedRoutes.forEach((route) => {
      console.log(`
        بلاغ ${route.reportId} → وحدة ${route.unit} | ${route.distanceKm} كم | ${route.durationMin} دقيقة
      `);
    });
  } catch (err) {
    console.error("خطأ أثناء التنفيذ:", err);
  } finally {
    sql.close();
  }
}

// استدعاء الدالة كل 5 ثواني
setInterval(calculateRoutes, 5000);

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
