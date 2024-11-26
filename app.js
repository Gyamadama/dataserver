require('dotenv').config();
const express = require('express');
const path = require('path');
const mysql = require('mysql2/promise'); // promise 버전으로 설정
const cors = require('cors');
const crypto = require('crypto');
const app = express();
const nodemailer = require('nodemailer');
const multer = require('multer');
const session = require('express-session');
const upload = multer({
    storage: multer.memoryStorage(),
    limits: {fileSize:16*1024*1024}, //16MB제한
});
const secretKey = crypto.randomBytes(32).toString('hex'); // 32 바이트 길이의 무작위 문자열 생성
const http = require('http');
const { exec } = require('child_process'); // 서버 재시작 명령 실행

// 서버 인스턴스 생성
const server = http.createServer(app);
const BASE_PORT = process.env.BASE_PORT;
const BASE_URL = process.env.BASE_URL;
// Winston 로깅 추가
const winston = require('winston');
// 세션 설정
app.use(session({
    secret: secretKey, // 세션을 위한 고유한 키 설정
    resave: false, // 요청 중 아무런 수정이 없어도 세션을 저장하지 않도록 설정
    saveUninitialized: false, // 초기화되지 않은 세션을 저장하지 않음
    rolling: true, // 요청 시마다 세션 만료 시간 갱신
    cookie: {
        maxAge: 60 * 60 * 1000 // 세션 만료 시간 설정 (10분)
    }
}));
// 로거
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.File({ filename: 'error.log', level: 'error' }),
        new winston.transports.File({ filename: 'combined.log' })
    ]
});

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// 동적 import()를 사용하여 mime 모듈을 불러옴
let mime;
(async () => {
    mime = await import('mime');
})();

// MySQL 풀 설정
const pool = mysql.createPool({
    host: process.env.MYSQL_HOST,
    user: process.env.MYSQL_ID,
    password: process.env.MYSQL_PWD,
    database: process.env.MYSQL_DB,
    connectionLimit: process.env.MYSQL_CONNECTION_LIMIT
});

const transporter = nodemailer.createTransport({
    service: process.env.SMTP_SERVICE,
    host: process.env.SMTP_HOST,
    tls: true,
    port: process.env.SMTP_PORT,
    auth: {
        user: process.env.NAVER_USER,
        pass: process.env.NAVER_PASS
    }
});



// 세션 만료 체크 미들웨어
function sessionCheck(req, res, next) {
    if (!req.session.userId) {
        // 항상 JSON 반환
        return res.status(401).json({
            success: false,
            message: '세션이 만료되었습니다. 다시 로그인해주세요.',
        });
    }
    next();
}

app.use((req, res, next) => {
    const unprotectedRoutes = ['/', '/login', '/signup','/config' ,'/estimate-request', '/login.html', '/signup.html', '/quotes.html'];
    if (unprotectedRoutes.includes(req.path)) {
        return next(); // 세션 체크 제외
    }
    sessionCheck(req, res, next); // 세션 체크
});

// CORS 설정 // CORS 설정 및 JSON 파싱 미들웨어 추가
app.use(cors({
    origin: BASE_URL + BASE_PORT, // 클라이언트의 출처 (URL)
    credentials: true // 클라이언트 요청에 인증 정보를 포함할 수 있도록 허용
}));

// 요청 로그 미들웨어 추가
app.use((req, res, next) => {
    const log = `
    [${new Date().toISOString()}] ${req.method} ${req.originalUrl} 
    IP: ${req.ip} 
    Body: ${JSON.stringify(req.body)}\n`;
    console.log(log);
    next();
});

// 비밀번호 해싱 함수
function hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('base64');
}




// 루트 경로에 접속했을 때 login.html로 리디렉션
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});


// 회원가입 API
app.post('/signup', async (req, res) => {
    const { userId, password, name, phone, school, position, officePhone, email } = req.body;
    try {
        const hashedPassword = hashPassword(password);
        const query = 'INSERT INTO sys.account (ID, PWD, NAME, PHONE, SCHOOL, POSITION, TEL, EMAIL) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
        await pool.query(query, [userId, hashedPassword, name, phone, school, position, officePhone, email]);
        res.status(201).json({ success: true, message: '회원가입이 완료되었습니다.' });
    } catch (error) {
        handleError(res, error);
    }
});

// 로그인 API
app.post('/login', async (req, res) => {
    const { userId, password } = req.body;
    try {
        const query = 'SELECT * FROM sys.account WHERE ID = ?';
        const [results] = await pool.query(query, [userId]);
        if (results.length === 0) {
            res.status(401).json({ success: false, message: '아이디 또는 비밀번호가 잘못되었습니다.' });
            return;
        }
        const user = results[0];
        const hashedInputPassword = hashPassword(password);
        if (hashedInputPassword === user.PWD) {
            req.session.userId = userId;
            req.session.userFrom = user.FROM;
            res.status(200).json({ success: true, message: '로그인 성공', from: user.FROM });
        } else {
            res.status(401).json({ success: false, message: '아이디 또는 비밀번호가 잘못되었습니다.' });
        }
    } catch (error) {
        handleError(res, error);
    }
});

// 로그아웃 API
app.post('/logout', (req, res) => {
    try {
        if (req.session) {
            req.session.destroy(err => {
                if (err) {
                    res.status(500).json({ success: false, message: '로그아웃 중 오류가 발생했습니다.' });
                } else {
                    res.status(200).json({ success: true, message: '로그아웃 성공' });
                }
            });
        } else {
            res.status(200).json({ success: true, message: '로그아웃 성공' });
        }
    } catch (error) {
        handleError(res, error);
    }
});

// 학교 정보 조회 API
app.get('/schoolinfo', async (req, res) => {
    const userFrom = req.query.from;
    try {
        const query = userFrom === 'admin'
            ? `SELECT * FROM sys.school`
            : `SELECT * FROM sys.school WHERE school_id = ?`;
        const [results] = await pool.query(query, [userFrom]);
        res.status(200).json(results);
    } catch (error) {
        handleError(res, error);
    }
});


// 유저정보 조회 API
app.get('/userinfo', async (req, res) => {
    try {
        const query = `SELECT * FROM sys.account`;
        const [results] = await pool.query(query);
        res.status(200).json({ success: true, data: results });
    } catch (error) {
        handleError(res, error);
    }
});

/* 사용자 정보 업데이트 API */
app.post('/userinfoupdate', async (req, res) => {
    const updates = req.body; // 수정된 데이터 배열

    try {
        // 업데이트 쿼리 생성
        const queries = updates.map(update => {
            const query = `
                UPDATE sys.account
                SET \`FROM\` = ?
                WHERE NO = ?;
            `;
            const params = [update.user_from, update.user_id];
            return { query, params };
        });

        // 모든 업데이트 쿼리를 실행
        const results = await Promise.all(
            queries.map(q => pool.query(q.query, q.params))
        );

        // 결과 반환
        res.status(200).json({ message: '변경 사항이 저장되었습니다.', results });
    } catch (error) {
        handleError(res, error); // 공통 에러 처리 함수 사용
    }
});

/* 장비정보값조회 APU */
app.get('/eqselectinfo', async (req, res) => {
    const searchTerm = req.query.search ? `%${req.query.search}%` : '%';
    const from = req.query.from;
    try {
        const query = `
            SELECT * FROM sys.school_info
            WHERE school_id LIKE ?
              AND (
                   eq_no LIKE ?
                   OR deviceType LIKE ?
                   OR manufacturer LIKE ?
                   OR modelName LIKE ?
                   OR precount LIKE ?
                   OR presize LIKE ?
                   OR mediumcount LIKE ?
                   OR mediumsize LIKE ?
                   OR hepacount LIKE ?
                   OR hepasize LIKE ?
                   OR location LIKE ?
                   OR replaceday LIKE ?
                   OR cleanday LIKE ?
                   OR particulas LIKE ?
               )
        `;
        const [results] = await pool.query(query, [
            from, searchTerm, searchTerm, searchTerm, searchTerm,
            searchTerm, searchTerm, searchTerm, searchTerm, searchTerm,
            searchTerm, searchTerm, searchTerm, searchTerm, searchTerm
        ]);
        res.status(200).json(results);
    } catch (error) {
        handleError(res, error); // 공통 에러 처리 함수 사용
    }
});


// 유저정보선택조회 API
app.get('/userselectinfo', async (req, res) => {
    const searchTerm = req.query.search ? `%${req.query.search}%` : '%';
    try {
        const query = `
            SELECT * FROM sys.account
            WHERE NO LIKE ? 
               OR ID LIKE ? 
               OR NAME LIKE ?
               OR PHONE LIKE ?
               OR SCHOOL LIKE ?
               OR POSITION LIKE ?
               OR TEL LIKE ?
               OR EMAIL LIKE ?
               OR \`FROM\` LIKE ?
        `;
        const [results] = await pool.query(query, Array(9).fill(searchTerm));
        res.status(200).json(results);
    } catch (error) {
        handleError(res, error); // 공통 에러 처리 함수 사용
    }
});

// 학교정보선택조회 API
app.get('/schoolselectinfo', async (req, res) => {
    const searchTerm = req.query.search ? `%${req.query.search}%` : '%';
    try {
        const query = `
            SELECT * FROM sys.school
            WHERE school_id LIKE ? 
               OR school_name LIKE ? 
               OR school_grade LIKE ?
               OR school_create LIKE ?
               OR school_type LIKE ?
               OR school_address1 LIKE ?
               OR school_address2 LIKE ?
               OR school_info LIKE ?
               OR school_inspection LIKE ?
               OR school_md LIKE ?
               OR school_nextinfo LIKE ?
               OR school_particulas LIKE ?
        `;
        const [results] = await pool.query(query, Array(12).fill(searchTerm));
        res.status(200).json(results);
    } catch (error) {
        handleError(res, error); // 공통 에러 처리 함수 사용
    }
});

// 장비 정보 조회 API
app.get('/equipmentinfo', async (req, res) => {
    const { from, currentschool } = req.query;
    try {
        const query = `SELECT * FROM sys.school_info WHERE school_id = ?`;
        const [results] = await pool.query(query, [from === 'admin' ? currentschool : from]);
        res.status(200).json(results);
    } catch (error) {
        handleError(res, error);
    }
});

// 보고서 데이터 조회 API
app.get('/reportdata', async (req, res) => {
    const { school_id, currentschool } = req.query;
    try {
        const query = `SELECT * FROM sys.report WHERE school_id = ?`;
        const [results] = await pool.query(query, [school_id === 'admin' ? currentschool : school_id]);
        res.status(200).json({ success: true, data: results });
    } catch (error) {
        handleError(res, error);
    }
});

// 보고서 데이터 다운로드 API (모든 파일 확장자에 대응)
app.get('/reportdown', async (req, res) => {
    const { school_id, no } = req.query;
    try {
        const query = `
            SELECT report_date, report_filename, report_down
            FROM sys.report 
            WHERE school_id = ? AND report_no = ?
        `;
        const [results] = await pool.query(query, [school_id === 'admin' ? req.query.currentschool : school_id, no]);

        if (results.length === 0 || !results[0].report_down) {
            return res.status(404).json({ success: false, message: '보고서 데이터가 존재하지 않습니다.' });
        }

        const report = results[0];
        const filename = report.report_filename || `report_${no}`;
        const extension = path.extname(filename) || '.pdf';
        const mimeType = mime.default.getType(extension) || 'application/octet-stream';
        const safeFilename = encodeURIComponent(filename).replace(/['()]/g, escape);

        res.setHeader('Content-Type', mimeType);
        res.setHeader('Content-Disposition', `attachment; filename="${safeFilename}"`);
        res.status(200).send(report.report_down);
    } catch (error) {
        handleError(res, error); // 공통 에러 처리 함수 사용
    }
});

// 견적 요청 API
app.post('/estimate-request', upload.any(), async (req, res) => {
    try {
        // 입력 데이터 가져오기
        const {
            schoolName,
            contactPerson,
            email,
            annualVisit,
            annualFilterChange,
            details,
            equipment,
            manufacturer,
            model,
            quantity
        } = req.body;

        // 데이터 유효성 검증
        if (!schoolName || !contactPerson || !email || !equipment) {
            return res.status(400).json({ success: false, message: '필수 입력 데이터가 누락되었습니다.' });
        }

        // 장비 정보 처리
        const equipmentArray = Array.isArray(equipment) ? equipment : [equipment];
        const manufacturersArray = Array.isArray(manufacturer) ? manufacturer : [manufacturer];
        const modelsArray = Array.isArray(model) ? model : [model];
        const quantitiesArray = Array.isArray(quantity) ? quantity : [quantity];

        let equipmentDetails = '';
        equipmentArray.forEach((item, index) => {
            const manufacturer = manufacturersArray[index] || '정보 없음';
            const model = modelsArray[index] || '정보 없음';
            const quantity = quantitiesArray[index] || '정보 없음';

            equipmentDetails += `
                <tr>
                    <td>${index + 1}</td>
                    <td>${item}</td>
                    <td>${manufacturer}</td>
                    <td>${model}</td>
                    <td>${quantity}</td>
                </tr>
            `;
        });

        // 이메일 본문 HTML 생성
        const mailText = `
            <p><strong>기관명:</strong> ${schoolName}</p>
            <p><strong>연락처:</strong> ${contactPerson}</p>
            <p><strong>이메일:</strong> ${email}</p>
            <p><strong>연간 방문 횟수:</strong> ${annualVisit}</p>
            <p><strong>연간 필터 교체 횟수:</strong> ${annualFilterChange}</p>
            <p><strong>기타 문의사항:</strong> ${details}</p>
            <h3>보유 기기 정보:</h3>
            <table border="1" cellpadding="5" cellspacing="0" style="border-collapse: collapse; width: 100%;">
                <thead>
                    <tr>
                        <th>번호</th>
                        <th>장비 종류</th>
                        <th>제조업체명</th>
                        <th>모델명</th>
                        <th>보유 대수</th>
                    </tr>
                </thead>
                <tbody>
                    ${equipmentDetails}
                </tbody>
            </table>
        `;

        // 이메일 옵션 설정
        const mailOptions = {
            from: process.env.NAVER_USER,
            to: process.env.ESTIMATE_RECIPIENT, // 이메일 수신자
            subject: `[MOKKOJI] ${schoolName} 견적 요청`,
            html: mailText,
            attachments: req.files.map(file => ({
                filename: Buffer.from(file.originalname, 'latin1').toString('utf8'),
                content: file.buffer,
                contentType: file.mimetype
            }))
        };

        // 이메일 발송
        await transporter.sendMail(mailOptions);

        // 성공 응답
        res.status(200).json({ success: true, message: '견적 요청이 성공적으로 접수되었습니다.' });
    } catch (error) {
        handleError(res, error); // 공통 에러 처리 함수 사용
    }
});


// /saveEquipmentInfo API
app.post('/saveEquipmentInfo', async (req, res) => {
    
    const equipmentData = req.body; // 배열 형태로 받아옵니다
    const school_id = req.query.from;
    const userId = req.query.userId;
    let connection;

    try {
        if (!school_id) {
            return res.status(400).json({ success: false, message: 'school_id가 필요합니다.' });
        }

        connection = await pool.getConnection();

        // 트랜잭션 시작
        await connection.beginTransaction();

        // Step 1: 클라이언트로부터 전달된 eq_no 목록 추출
        const newEqNos = equipmentData.map(equipment => equipment.eq_no);

        // Step 2: 기존 데이터와 비교하여 삭제할 목록 찾기
        const [existingData] = await connection.query(
            'SELECT eq_no FROM sys.school_info WHERE school_id = ?',
            [school_id]
        );
        const existingEqNos = existingData.map(row => row.eq_no);

        // 기존 데이터 중 새 데이터에 없는 항목 삭제 (차등 업데이트)
        const toDelete = existingEqNos.filter(eq_no => !newEqNos.includes(eq_no));
        if (toDelete.length > 0) {
            await connection.query(
                'DELETE FROM sys.school_info WHERE school_id = ? AND eq_no IN (?)',
                [school_id, toDelete]
            );
        }

        // Step 3: 요청된 데이터 삽입/업데이트
        const insertOrUpdateQuery = `
            INSERT INTO sys.school_info (
                school_id, eq_no, deviceType, manufacturer, modelName, precount, presize,
                mediumcount, mediumsize, hepacount, hepasize, location,replaceday,cleanday, particulas
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?,?)
            ON DUPLICATE KEY UPDATE
                deviceType = VALUES(deviceType),
                manufacturer = VALUES(manufacturer),
                modelName = VALUES(modelName),
                precount = VALUES(precount),
                presize = VALUES(presize),
                mediumcount = VALUES(mediumcount),
                mediumsize = VALUES(mediumsize),
                hepacount = VALUES(hepacount),
                hepasize = VALUES(hepasize),
                location = VALUES(location),
                replaceday = VALUES(replaceday),
                cleanday = VALUES(cleanday),
                particulas = VALUES(particulas)
        `;

        for (const equipment of equipmentData) {
            const {
                eq_no,
                deviceType,
                manufacturer,
                modelName,
                precount,
                presize,
                mediumcount,
                mediumsize,
                hepacount,
                hepasize,
                location,
                replaceday,
                cleanday,
                particulas

            } = equipment;

            await connection.query(insertOrUpdateQuery, [
                school_id,
                eq_no,
                deviceType,
                manufacturer,
                modelName,
                precount,
                presize,
                mediumcount,
                mediumsize,
                hepacount,
                hepasize,
                location,
                replaceday,
                cleanday,
                particulas
            ]);
        }

        // Step 4: sys.school 테이블 업데이트
        const today = new Date();
        const nextReplacementDate = new Date(today);
        nextReplacementDate.setMonth(today.getMonth() + 6); // 6개월 후 날짜 설정

        const formattedToday = today.toISOString().split('T')[0];
        const formattedNextReplacement = nextReplacementDate.toISOString().split('T')[0];

        // school_info, school_md, school_nextinfo 필드 업데이트
        await connection.query(
            `UPDATE sys.school
             SET school_inspection = ?, school_nextinfo = ?
             WHERE school_id = ?`,
            [formattedToday, formattedNextReplacement, school_id]
        );

        // 트랜잭션 커밋
        await connection.commit();
        connection.release();

        res.json({ success: true, message: '장비 정보가 성공적으로 저장되었습니다.' });
    } catch (error) {
        console.error('장비 정보 저장 중 오류 발생:', error);

        // 트랜잭션 롤백
        if (connection) await connection.rollback();
        if (connection) connection.release();

        res.status(500).json({ success: false, message: '장비 정보 저장 중 오류가 발생했습니다.', error: error.message });
    }
});

// 학교 정보 업데이트 API (배열 처리)
app.post('/updateSchools', async (req, res) => {
    const schools = req.body; // 배열 형태로 데이터를 받음

    if (!Array.isArray(schools) || schools.length === 0) {
        return res.status(400).json({
            success: false,
            message: '유효한 데이터 배열이 필요합니다.',
        });
    }
 
    const query = `
        UPDATE sys.school
        SET school_info = ?, 
            school_md = ?,
            school_particulas = ?
        WHERE school_id = ?
    `;

    const connection = await pool.getConnection();
    try {
        // 트랜잭션 시작
        await connection.beginTransaction();

        const [userResult] = await connection.query(
            'SELECT NAME FROM sys.account WHERE ID = ?',
            [req.body[0].school_md]
        );

        if (userResult.length === 0) {
            throw new Error('해당 사용자 ID를 찾을 수 없습니다.');
        }

        const userName = userResult[0].NAME;

        // 배열 데이터를 처리
        for (const school of schools) {
            const { school_id, school_info, school_particulas } = school;

            if (!school_id) {
                throw new Error(`school_id가 없습니다. 요청 데이터: ${JSON.stringify(school)}`);
            }

            // 기존 데이터 가져오기
            const [existingData] = await connection.query(
                'SELECT school_info, school_particulas FROM sys.school WHERE school_id = ?',
                [school_id]
            );

            if (existingData.length === 0) {
                throw new Error(`school_id ${school_id}에 해당하는 데이터가 없습니다.`);
            }

            const existingSchool = existingData[0];

            // 기존 데이터와 클라이언트 데이터를 병합
            const mergedData = {
                school_info: school_info !== undefined ? school_info : existingSchool.school_info,
                school_particulas: school_particulas !== undefined ? school_particulas : existingSchool.school_particulas,
            };

            // SQL 실행
            await connection.query(query, [
                mergedData.school_info,
                userName,
                mergedData.school_particulas,
                school_id,
            ]);
        }

        // 트랜잭션 커밋
        await connection.commit();
        connection.release();

        res.json({
            success: true,
            message: '모든 학교 정보가 성공적으로 업데이트되었습니다.',
        });
    } catch (error) {
        // 트랜잭션 롤백
        if (connection) await connection.rollback();
        connection.release();

        console.error('학교 정보 업데이트 중 오류 발생:', error);
        res.status(500).json({
            success: false,
            message: '학교 정보를 업데이트하는 중 오류가 발생했습니다.',
        });
    }
});

app.post('/uploadReport', upload.any(), async (req, res) => {
    const { currentschool } = req.query; // 학교 ID를 쿼리로 받음
    const { no, date, size } = req.body; // 클라이언트에서 전송된 추가 데이터

    try {
        // 요청 데이터 디버깅
        console.log('req.files:', req.files); // 업로드된 파일 확인
        console.log('req.body:', req.body); // 기타 데이터 확인

        if (!req.files || req.files.length === 0) {
            return res.status(400).json({ success: false, message: '파일이 업로드되지 않았습니다.' });
        }

        // MySQL 쿼리 작성
        const query = `
            INSERT INTO sys.report (school_id, report_no, report_down, report_date, report_filename, report_size)
            VALUES (?, ?, ?, ?, ?, ?)
        `;

        // 첫 번째 파일만 처리 (다중 파일의 경우 반복문 사용)
        const file = req.files[0];
        const fileName = Buffer.from(file.originalname, 'latin1').toString('utf8');
        const formattedDate = new Date(date).toISOString().split('T')[0]; // YYYY-MM-DD 형식

        // 파라미터 준비
        const params = [
            currentschool, // 학교 ID
            no, // 보고서 번호
            file.buffer, // 파일 내용 (MEDIUMBLOB)
            formattedDate, // 게시일
            fileName, // 원본 파일명
            size // 파일 크기
        ];

        // 데이터베이스에 삽입
        const [result] = await pool.query(query, params);

        // 성공 응답
        res.json({
            success: true,
            message: '파일이 성공적으로 업로드되었습니다.',
            result
        });
    } catch (error) {
        console.error('DB 저장 중 오류 발생:', error);
        res.status(500).json({
            success: false,
            message: 'DB 저장 중 오류가 발생했습니다.',
            error: error.message
        });
    }
});

// 보고서 삭제 API
app.delete('/deleteReport', async (req, res) => {
    const { report_no, school_id } = req.query;
    try {
        const query = `DELETE FROM sys.report WHERE report_no = ? AND school_id = ?`;
        const [result] = await pool.query(query, [report_no, school_id]);
        if (result.affectedRows === 0) {
            res.status(404).json({ success: false, message: '삭제할 보고서를 찾을 수 없습니다.' });
        } else {
            res.status(200).json({ success: true, message: '보고서가 성공적으로 삭제되었습니다.' });
        }
    } catch (error) {
        handleError(res, error);
    }
});

// Graceful Shutdown 추가(요청중단방지, 데이터유실방지)
process.on('SIGINT', () => {
    console.log('서버가 종료 신호(SIGINT)를 수신했습니다.');
    server.close(() => {
        console.log('모든 요청 처리가 완료되어 서버가 안전하게 종료됩니다.');
        process.exit(0);
    });

    // 일정 시간 후 강제 종료 (예: 10초)
    setTimeout(() => {
        console.error('강제 종료 중...');
        process.exit(1);
    }, 10000);
});

process.on('SIGTERM', () => {
    console.log('서버가 종료 신호(SIGTERM)를 수신했습니다.');
    server.close(() => {
        console.log('모든 요청 처리가 완료되어 서버가 안전하게 종료됩니다.');
        process.exit(0);
    });
});

// 서버 실행 함수
function startServer() {
    server.listen(BASE_PORT, () => {
        console.log(`서버가 ${BASE_URL}${BASE_PORT} 에서 실행 중입니다.`);
    });
}
// 서버 재시작 함수
function restartServer() {
    console.log('서버를 재시작합니다...');
    // Node.js 서버를 안전하게 종료 후 재시작
    server.close(() => {
        console.log('서버가 종료되었습니다. 재시작 중...');
        exec('node app.js', (error, stdout, stderr) => {
            if (error) {
                console.error('서버 재시작 실패:', error);
                process.exit(1); // 재시작 실패 시 프로세스 종료
            } else {
                console.log('서버가 성공적으로 재시작되었습니다.');
                console.log(stdout || stderr);
            }
        });
    });
}

// 공통 에러 처리 함수
function handleError(res, error) {
    console.error('API 처리 중 오류 발생:', error);
    if (error.code) {
        // 데이터베이스 또는 기타 커스텀 에러 코드가 있을 경우
        res.status(500).json({ success: false, code: error.code, message: error.message });
    } else {
        // 일반적인 서버 오류 처리
        res.status(500).json({ success: false, message: '서버 오류가 발생했습니다.' });
    }
}

// uncaughtException 처리
process.on('uncaughtException', (err) => {
    logger.error(`Uncaught Exception: ${err.stack}`);
    restartServer(); // 서버 재시작 호출
});

// unhandledRejection 처리
process.on('unhandledRejection', (reason, promise) => {
    logger.error(`Unhandled Rejection at: ${promise} reason: ${reason}`);
    restartServer(); // 서버 재시작 호출
});

// 서버 시작
startServer();

