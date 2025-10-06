// تحميل المكتبات اللازمة، يحمل ملف . اينف الموجود في ملف المشروع ، ينقل مل المتغيرات الي في الى بروسيس. اينف  المتغيرات دي تستخدم للسريل
// DB_USER و DB_PASS و DB_SERVER و DB_NAME و PORTمثال اسم متغير لازم يكو
// تحميل المكتبات
require('dotenv').config();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt'); // لازم نضيفه علشان register/login
const express = require('express');      // استدعاء مكتبة اكسبريس لعمل سيرفر ويب بسيط     
const sql = require('mssql');      // استدعاء مكتبة mssql للاتصال بقاعدة بيانات SQL Server
// إنشاء تطبيق اكسبريس
const app = express();
app.use(express.json()); //  مفعّل ميزة قراءة جسم الطلب بصيغة جيسون
// الهدف من السطر ان الاي بي اي  بتاعي يقدر  يستقبل بيانات من نوع جيسون

// إعداد اتصال قاعدة البيانات
const dbConfig = {
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    server: process.env.DB_SERVER,
    database: process.env.DB_NAME,
    //   تحدد مكان وقيم الاتصال بقاعدة البيانات(السطور من 12 الي 16)، اقرأ قيم هذه المتغيرات من ملف .اينف
    options: {
        encrypt: true,
        // يعني اتصال مشفر
        trustServerCertificate: true
        // يعني يثق في شهادة السيرفر حتى لو كانت غير موثوقة، مهم في بيئات التطوير المحلية ة
        // لو انت في بيئة انتاج و عندك شهادة موثوقة لازم تخليها false
        // لو انت في بيئة تطوير محلية و مش عندك شهادة موثوقة لازم تخليها true
    },
    pool: { max: 10, min: 0, idleTimeoutMillis: 30000 } // إعدادات تجمع الاتصالات ، بتحدد اقصى عدد اتصالات ممكنة في التجمع و اقل عدد اتصالات و وقت الانتظار قبل اغلاق الاتصال الغير مستخدم
};

// Middleware لفحص الـ Token
// نظراً لأن بعض المسارات ممكن تحتاج توثيق، هنستخدم ميدلوير لفحص التوكن في الهيدر بتاع الريكوست  
//  الهدف من الميدلوير ده انه يفحص التوكن في الهيدر بتاع الريكوست
const jwt = require('jsonwebtoken'); // استدعاء مكتبة jsonwebtoken للتعامل مع التوكن
function authenticateToken(req, res, next) { // دالة ميدلوير لفحص التوكن
    const authHeader = req.headers['authorization']; // استخراج الهيدر بتاع التوثيق
    // الهيدر
    const token = authHeader && authHeader.split(' ')[1]; // استخراج التوكن من الهيدر
    if (!token) return res.sendStatus(401); // لو مفيش توكن يرجع 401
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => { // التحقق من صحة التوكن باستخدام السر المخفي
        if (err) return res.sendStatus(403); // لو التوكن غير صالح يرجع 403
        req.user = user; // لو التوكن صالح يحط بيانات المستخدم في الريكوست
        next(); // ينادي الميدلوير التالي
    });
    // تسجيل مستخدم جديد
    app.post('/register', async (req, res) => { // مسار تسجيل مستخدم جديد
        const { username, email, password, role } = req.body; // استخراج الحقول المطلوبة من جسم الطلب
        if (!username || !email || !password) {      // التحقق من وجود جميع الحقول المطلوبة في جسم الطلب
            return res.status(400).json({ error: 'missing fields' });   // لو في حقل ناقص يرجع خطأ 400 مع رسالة
        }
        try {                                                    // محاولة تنفيذ الكود
            const hashedPassword = await bcrypt.hash(password, 10);  // تشفير كلمة المرور باستخدام bcrypt

            await sql.connect(dbConfig); // الاتصال بقاعدة البيانات
            const request = new sql.Request();  // إنشاء طلب جديد
            request.input('UserName', sql.NVarChar(100), username);  // تعريف بارامتر اسم المستخدم
            request.input('Email', sql.NVarChar(150), email);    // تعريف بارامتر البريد الإلكتروني
            request.input('Role', sql.NVarChar(50), role || 'User');   // تعريف بارامتر الدور (افتراضي "User" لو مش موجود)
            const result = await request.query(                       // تنفيذ استعلام الإدخال في جدول المستخدمين
                `INSERT INTO Users (UserName, Email, Role)
       OUTPUT INSERTED.UserID
       VALUES (@UserName, @Email, @Role)`
            );
            const userId = result.recordset[0].UserID;         // الحصول على معرف المستخدم الذي تم إنشاؤه

            await new sql.Request()                                // إنشاء طلب جديد لإدخال بيانات تسجيل الدخول
                .input('UserID', sql.Int, userId)                       // تعريف بارامتر معرف المستخدم
                .input('Email', sql.NVarChar(150), email)                   // تعريف بارامتر البريد الإلكتروني
                .input('PasswordHash', sql.NVarChar(255), hashedPassword)   // تعريف بارامتر كلمة المرور المشفرة
                .query(`INSERT INTO Login_Users (UserID, Email, PasswordHash) VALUES (@UserID, @Email, @PasswordHash)`);  // تنفيذ استعلام الإدخال في جدول تسجيل الدخول

            res.status(201).json({ ok: true, userId });         //يرجع 201 مع اوكي ترو و معرف المستخدم لو كل حاجة مشت تمام
        } catch (err) {                                             // لو في اي خطأ حصل في البلوك بتاع التراي
            res.status(500).json({ error: err.message });                        //يرجع 500 مع رسالة الخطأ
        } finally {                                                         // البلوك ده بيتنفذ دايما سواء حصل خطأ او لا
            sql.close();
        }
    });

    // تسجيل دخول
    app.post('/login', async (req, res) => {           // مسار تسجيل دخول
        const { email, password } = req.body;              // استخراج الحقول المطلوبة من جسم الطلب
        if (!email || !password) return res.status(400).json({ error: 'missing fields' });       // لو في حقل ناقص يرجع خطأ 400 مع رسالة

        try {
            await sql.connect(dbConfig); // الاتصال بقاعدة البيانات
            const request = new sql.Request();            // إنشاء طلب جديد
            request.input('Email', sql.NVarChar(150), email);       // تعريف بارامتر البريد الإلكتروني

            const result = await request.query(`SELECT u.UserID, u.UserName, u.Role, l.PasswordHash
                                        FROM Users u
                                        JOIN Login_Users l ON u.UserID = l.UserID
                                        WHERE l.Email = @Email`);
            // تنفيذ استعلام جلب بيانات المستخدم وكلمة المرور المشفرة
            if (result.recordset.length === 0) return res.status(401).json({ error: 'invalid credentials' }); // لو مفيش مستخدم بالبريد ده يرجع 401

            const user = result.recordset[0]; // الحصول على بيانات المستخدم
            const match = await bcrypt.compare(password, user.PasswordHash); // مقارنة كلمة المرور المدخلة مع الكلمة المشفرة في قاعدة البيانات
            // لو كلمة المرور مش متطابقة يرجع 401
            if (!match) return res.status(401).json({ error: 'invalid credentials' });

            const token = jwt.sign({ userId: user.UserID, role: user.Role }, process.env.JWT_SECRET, { expiresIn: '1h' }); // إنشاء توكن جديد يحتوي على معرف المستخدم والدور، صالح لمدة ساعة
            res.json({ token }); //يرجع التوكن لو كل حاجة مشت تمام
        } catch (err) { // لو في اي خطأ حصل في البلوك بتاع التراي
            res.status(500).json({ error: err.message });                       //يرجع 500 مع رسالة الخطأ
        } finally {
            sql.close();
        }
    });

    // إضافة بلاغ (الحالة افتراضيًا "جديد" = 1)
    app.post('/report', authenticateToken, async (req, res) => {  // مسار إضافة بلاغ، محمي بميدلوير التوثيق
        const { unitId, locationWKT } = req.body;                  // استخراج الحقول المطلوبة من جسم الطلب
        const userId = req.user.userId;                             // استخراج معرف المستخدم من التوكن

        if (!unitId || !locationWKT) {                          // التحقق من وجود جميع الحقول المطلوبة في جسم الطلب
            return res.status(400).json({ error: 'missing fields' }); // لو في حقل ناقص يرجع خطأ 400 مع رسالة
        }

        try {                               // محاولة تنفيذ الكود
            await sql.connect(dbConfig);                // الاتصال بقاعدة البيانات باستخدام الإعدادات المحددة
            const request = new sql.Request();                 // إنشاء طلب جديد
            // تعريف بارامترات الإجراء المخزن
            request.input('UserID', sql.Int, userId);      // الاسم هنا يجب أن يطابق اسم البارامتر في الإجراء المخزن
            request.input('UnitID', sql.Int, unitId);         // نفس الكلام هنا القيمة الثالثة هي المتغير المرسل من الموبايل
            request.input('Report_StatusID', sql.Int, 1); // الحالة الافتراضية: جديد
            request.input('LocationWKT', sql.NVarChar(100), locationWKT);        // نفس الكلام هنا مع اختلاف النوع والطول وي كمان هنا الاجرء المخزن هيحول الموقع لما ياخده كنص الى ارقام علشان المشكله وجهتني وانا بصمم الاجرء المخزن

            await request.execute('AddReport'); // تنفيذ الإجراء المخزن
            // إرسال استجابة ناجحة
            res.status(201).json({ ok: true });
        } catch (err) {   // لو في اي خطأ حصل في البلوك بتاع التراي
            res.status(500).json({ error: err.message });                      //يرجع 500 مع رسالة الخطأ
        } finally {
            sql.close();
        }
    });

}
// مسار إضافة بلاغ POST
app.post('/report', async (req, res) => {                     // مسار API لاستقبال البلاغات
    const { userId, unitId, statusId, locationWKT } = req.body; // استخراج الحقول المطلوبة من جسم الطلب
    if (!userId || !unitId || !statusId || !locationWKT) {      // التحقق من وجود جميع الحقول المطلوبة في جسم الطلب
        return res.status(400).json({ error: 'missing fields' });
    } // لو في حقل ناقص يرجع خطأ 400 مع رسالة
});
try {
    await sql.connect(dbConfig); // الاتصال بقاعدة البيانات باستخدام الإعدادات المحددة
    // إنشاء طلب جديد
    const request = new sql.Request();    //ينشئ ريكوست جديد. هذا كائن لإرسال بارامترات ونداء للإجراءات المخزنة
    request.input('UserID', sql.Int, userId); //ي  هنا بيعرف بارامتر اسمه يوزر اي دي من نوع انت و بقيمة يوزر اي دي اللي جايه من جسم الطلب
    request.input('UnitID', sql.Int, unitId); // الاسم هنا يجب أن يطابق اسم البارامتر في الإجراء المخزن
    request.input('Report_StatusID', sql.Int, statusId); // نفس الكلام هنا القيمة الثالثة هي المتغير المرسل من الموبايل
    request.input('LocationWKT', sql.NVarChar(100), locationWKT); // نفس الكلام هنا مع اختلاف النوع والطول وي كمان هنا الاجرء المخزن هيحول الموقع لما ياخده كنص الى ارقام علشان المشكله وجهتني وانا بصمم الاجرء المخزن
    // تنفيذ الإجراء المخزن
    await request.execute('AddReport'); // بينفذ الاجرء المخزن اللي اسمه اد ريبورت
    // إرسال استجابة ناجحة
    res.status(201).json({ ok: true }); //يرجع 201 مع اوكي ترو لو كل حاجة مشت تمام
} catch (err) { // لو في اي خطأ حصل في البلوك بتاع التراي
    console.error('Database error:', err); // يطبع الخطأ في الكونسول
    res.status(500).json({ error: err.message }); //يرجع 500 مع رسالة الخطأ
} finally { // البلوك ده بيتنفذ دايما سواء حصل خطأ او لا
    sql.close(); // بيقفل الاتصال بقاعدة البيانات
}
//   مسار جلب البلاغات GET
app.get('/reports', async (req, res) => {                   // مسار اي بي اي لجلب جميع البلاغات
    try {                                                     // محاولة الاتصال بقاعدة البيانات
        await sql.connect(dbConfig);                             // الاتصال بقاعدة البيانات
        // تنفيذ الإجراء المخزن
        const result = await new sql.Request().execute('GetReports');    // بينفذ الاجرء المخزن اللي اسمه جت ريبورتس
        // إرسال استجابة ناجحة مع البيانات
        res.json(result.recordset);        //يحتوي الصفوف التي رجعها الإجراء.
    } catch (err) {                                    // لو في اي خطأ حصل في البلوك بتاع التراي
        res.status(500).json({ error: err.message });   //يرجع 500 مع رسالة الخطأ
    } finally {                          // البلوك ده بيتنفذ دايما سواء حصل خطأ او لا
        sql.close();                   // بيقفل الاتصال بقاعدة البيانات
    }
});
//مسار جلب الوحدات GET
app.get('/units', async (req, res) => {             // مسار اي بي اي لجلب جميع الوحدات
    try {                                               // محاولة الاتصال بقاعدة البيانات
        await sql.connect(dbConfig);                      // الاتصال بقاعدة البيانات
        const result = await new sql.Request().execute('GetUnits');    // بينفذ الاجرء المخزن اللي اسمه جت يونيتس
        res.json(result.recordset);                                     //يحتوي الصفوف التي رجعها الإجراء.
    } catch (err) {                                                  // لو في اي خطأ حصل في البلوك بتاع التراي
        res.status(500).json({ error: err.message });                        //يرجع 500 مع رسالة الخطأ
    } finally {                                                   // البلوك ده بيتنفذ دايما سواء حصل خطأ او لا
        sql.close();                                                      // بيقفل الاتصال بقاعدة البيانات
    }
});
app.get('/statuses', authenticateToken, async (req, res) => { // مسار اي بي اي لجلب جميع حالات البلاغات، محمي بميدلوير التوثيق
    try {
        await sql.connect(dbConfig);                            // الاتصال بقاعدة البيانات
        const result = await new sql.Request().execute('GetStatuses');  // بينفذ الاجرء المخزن اللي اسمه جت ستاتوسيس
        res.json(result.recordset);                                   //يحتوي الصفوف التي رجعها الإجراء.
    } catch (err) {                                 // لو في اي خطأ حصل في البلوك بتاع التراي
        res.status(500).json({ error: err.message });                       //يرجع 500 مع رسالة الخطأ
    } finally {                                         // البلوك ده بيتنفذ دايما سواء حصل خطأ او لا
        sql.close();                                    // بيقفل الاتصال بقاعدة البيانات
    }
});
// تحديث حالة البلاغ
app.put('/report/:id/status', async (req, res) => { // مسار اي بي اي لتحديث حالة بلاغ معين
    const reportId = req.params.id;                       // استخراج معرف البلاغ من معلمات المسار
    const { statusId } = req.body;                         // استخراج معرف الحالة الجديد من جسم الطلب

    if (!statusId) {                                           // التحقق من وجود معرف الحالة في جسم الطلب
        return res.status(400).json({ error: 'statusId required' });              // لو معرف الحالة مش موجود يرجع خطأ 400 مع رسالة
    }

    try {                                                       // محاولة الاتصال بقاعدة البيانات
        await sql.connect(dbConfig);                                   // الاتصال بقاعدة البيانات
        const request = new sql.Request();                             // إنشاء طلب جديد
        request.input('ReportID', sql.Int, reportId);                         // تعريف بارامتر معرف البلاغ
        request.input('Report_StatusID', sql.Int, statusId);                     // تعريف بارامتر معرف الحالة الجديد
        // تنفيذ تحديث الحالة

        await request.query(`                                
      UPDATE Reports
      SET Report_StatusID = @Report_StatusID
      WHERE ReportID = @ReportID
    `); // بينفذ استعلام تحديث حالة البلاغ في قاعدة البيانات
        // إرسال استجابة ناجحة

        res.json({ ok: true });                          //يرجع اوكي ترو لو كل حاجة مشت تمام
    } catch (err) {                             // لو في اي خطأ حصل في البلوك بتاع التراي
        res.status(500).json({ error: err.message });                //يرجع 500 مع رسالة الخطأ
    } finally {                                           // البلوك ده بيتنفذ دايما سواء حصل خطأ او لا
        sql.close();                                     // بيقفل الاتصال بقاعدة البيانات
    }
});


// تشغيل السيرفر
const port = process.env.PORT || 3000;
app.listen(port, () => console.log('API running on port', port));








