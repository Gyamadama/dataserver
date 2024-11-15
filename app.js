const express = require('express');
const path = require('path');
const mysql = require('mysql2/promise'); // promise 버전으로 설정
const cors = require('cors');
const crypto = require('crypto');
const app = express();
const PORT = 5000;
const nodemailer = require('nodemailer');
const multer = require('multer');

const upload = multer({ storage: multer.memoryStorage() });

require('dotenv').config();

// 동적 import()를 사용하여 mime 모듈을 불러옴
let mime;
(async () => {
    mime = await import('mime');
})();

// MySQL 풀 설정
const pool = mysql.createPool({
    host: '218.156.106.25',
    user: 'root',
    password: 'mirae0216!',
    database: 'Mysql',
    connectionLimit: 100
});

const transporter = nodemailer.createTransport({
    service: 'Naver',
    host: 'smtp.naver.com',
    tls: true,
    port: 587,
    auth: {
        user: process.env.NAVER_USER,
        pass: process.env.NAVER_PASS
    }
});
// CORS 설정 및 JSON 파싱 미들웨어 추가
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// 루트 경로에 접속했을 때 login.html로 리디렉션
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

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

// 회원가입 API
app.post('/signup', async (req, res) => {
    const { userId, password, name, phone, school, position, officePhone, email } = req.body;

    try {
        const hashedPassword = hashPassword(password);
        const query = 'INSERT INTO sys.account (ID, PWD, NAME, PHONE, SCHOOL, POSITION, TEL, EMAIL) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
        await pool.query(query, [userId, hashedPassword, name, phone, school, position, officePhone, email]);
        res.json({ success: true, message: '회원가입이 완료되었습니다.' });
    } catch (error) {
        console.error('회원가입 중 오류 발생:', error);
        res.status(500).json({ success: false, message: '회원가입 중 오류가 발생했습니다.' });
    }
});

// 로그인 API
app.post('/login', async (req, res) => {
    const { userId, password } = req.body;
    const query = 'SELECT * FROM sys.account WHERE ID = ?';

    try {
        const [results] = await pool.query(query, [userId]);

        if (results.length === 0) {
            res.json({ success: false, message: '아이디 또는 비밀번호가 잘못되었습니다.' });
            return;
        }

        const user = results[0];
        const hashedInputPassword = hashPassword(password);

        if (hashedInputPassword === user.PWD) {
            res.json({ success: true, message: '로그인 성공', from: user.FROM });
        } else {
            res.json({ success: false, message: '아이디 또는 비밀번호가 잘못되었습니다.' });
        }
    } catch (error) {
        console.error('로그인 중 오류 발생:', error);
        res.status(500).json({ success: false, message: '로그인 중 오류가 발생했습니다.' });
    }
});

// 학교 정보 조회 API
app.get('/schoolinfo', async (req, res) => {
    const userFrom = req.query.from;
    let query = null;
    if (userFrom == 'admin') {
        query = `
        SELECT school_id, school_name, school_grade, school_create, school_type,
               school_address1, school_address2, school_info, school_md, school_nextinfo
        FROM sys.school
        `;
    } else {
        query = `
        SELECT school_id, school_name, school_grade, school_create, school_type,
               school_address1, school_address2, school_info, school_md, school_nextinfo
        FROM sys.school
        WHERE school_id = ?
        `;
    }
    

    try {
        const [results] = await pool.query(query, [userFrom]);
        res.json(results);
    } catch (error) {
        console.error('학교 정보를 가져오는 중 오류 발생:', error);
        res.status(500).json({ error: '데이터를 가져오는 중 오류가 발생했습니다.' });
    }
});


app.get('/eqselectinfo', async (req, res) => {
    const searchTerm = req.query.search ? `%${req.query.search}%` : '%';
    const query = `
        SELECT * FROM sys.school_info
        WHERE school_id LIKE ?
           OR eq_no LIKE ?
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
    `;

    try {
        const [results] = await pool.query(query, [searchTerm, searchTerm, searchTerm, searchTerm, searchTerm, searchTerm, searchTerm, searchTerm, searchTerm, searchTerm, searchTerm, searchTerm, searchTerm, searchTerm, searchTerm, searchTerm]);
        res.json(results);
    } catch (error) {
        console.error('데이터 조회 중 오류 발생:', error);
        res.status(500).json({ success: false, message: '데이터 조회 중 오류가 발생했습니다.' });
    }
});
// schoolselectinfo API
app.get('/schoolselectinfo', async (req, res) => {
    const searchTerm = req.query.search ? `%${req.query.search}%` : '%';
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
           OR school_md LIKE ?
           OR school_nextinfo LIKE ?
    `;

    try {
        const [results] = await pool.query(query, [searchTerm, searchTerm, searchTerm, searchTerm, searchTerm, searchTerm, searchTerm, searchTerm, searchTerm, searchTerm]);
        res.json(results);
    } catch (error) {
        console.error('데이터 조회 중 오류 발생:', error);
        res.status(500).json({ success: false, message: '데이터 조회 중 오류가 발생했습니다.' });
    }
});

// 장비 정보 조회 API
app.get('/equipmentinfo', async (req, res) => {
    const userFrom = req.query.from;
    const currentschool = req.query.currentschool;
    const query = `
    SELECT eq_no, deviceType, manufacturer, modelName, precount, presize,
            mediumcount, mediumsize, hepacount, hepasize, location
    FROM sys.school_info
    WHERE school_id = ?
    `;

    if (userFrom == 'admin') {
        try {
            const [results] = await pool.query(query, [currentschool]);
            res.json(results);
        } catch (error) {
            console.error('장비 정보를 가져오는 중 오류 발생:', error);
            res.status(500).json({ error: '장비 정보를 가져오는 중 오류가 발생했습니다.' });
        }
    } else {
        try {
            const [results] = await pool.query(query, [userFrom]);
            res.json(results);
        } catch (error) {
            console.error('장비 정보를 가져오는 중 오류 발생:', error);
            res.status(500).json({ error: '장비 정보를 가져오는 중 오류가 발생했습니다.' });
        }
    }
});

// 보고서 데이터 조회 API
app.get('/reportdata', async (req, res) => {
    const schoolId = req.query.school_id;
    const currentschool = req.query.currentschool;
    const query = `
        SELECT report_no, report_down, report_date, report_filename, report_size
        FROM sys.report 
        WHERE school_id = ?
        `;
    if (schoolId == 'admin') {
        try {
            const [results] = await pool.query(query, [currentschool]);

            const reports = results.map(report => ({
                report_no: report.report_no,
                report_down: report.report_down,
                report_filename: report.report_filename,
                report_date: report.report_date,
                report_size: report.report_size,
                hasReport: report.report_down !== null
            }));

            res.json({ success: true, data: reports });
        } catch (error) {
            console.error('보고서 데이터를 가져오는 중 오류 발생:', error);
            res.status(500).json({ error: '보고서 데이터를 가져오는 중 오류가 발생했습니다.' });
        }
    } else {
        try {
            const [results] = await pool.query(query, [schoolId]);

            const reports = results.map(report => ({
                report_no: report.report_no,
                report_down: report.report_down,
                report_filename: report.report_filename,
                report_date: report.report_date,
                report_size: report.report_size,
                hasReport: report.report_down !== null
            }));

            res.json({ success: true, data: reports });
        } catch (error) {
            console.error('보고서 데이터를 가져오는 중 오류 발생:', error);
            res.status(500).json({ error: '보고서 데이터를 가져오는 중 오류가 발생했습니다.' });
        }
    }
});

// 보고서 데이터 다운로드 API (모든 파일 확장자에 대응)
app.get('/reportdown', async (req, res) => {
    const schoolId = req.query.school_id;
    const no = req.query.no;
    const currentschool = req.query.currentschool;

    const query = `
        SELECT report_date, report_filename, report_down
        FROM sys.report 
        WHERE school_id = ? AND report_no = ?
    `;
    if (schoolId == 'admin') {
        try {
            const [results] = await pool.query(query, [currentschool, no]);

            if (results.length > 0 && results[0].report_down) {
                const report = results[0];
                const filename = report.report_filename || `report_${no}`;
                const extension = path.extname(filename) || '.pdf';
                const mimeType = mime.default.getType(extension) || 'application/octet-stream';

                const safeFilename = encodeURIComponent(filename).replace(/['()]/g, escape);
                res.setHeader('Content-Type', mimeType);
                res.setHeader('Content-Disposition', `attachment; filename="${safeFilename}"`);

                res.send(report.report_down);
            } else {
                res.status(404).json({ error: '보고서 데이터가 존재하지 않습니다.' });
            }
        } catch (error) {
            console.error('보고서 데이터를 가져오는 중 오류 발생:', error);
            res.status(500).json({ error: '보고서 데이터를 가져오는 중 오류가 발생했습니다.' });
        }
    } else {
        try {
            const [results] = await pool.query(query, [schoolId, no]);

            if (results.length > 0 && results[0].report_down) {
                const report = results[0];
                const filename = report.report_filename || `report_${no}`;
                const extension = path.extname(filename) || '.pdf';
                const mimeType = mime.default.getType(extension) || 'application/octet-stream';

                const safeFilename = encodeURIComponent(filename).replace(/['()]/g, escape);
                res.setHeader('Content-Type', mimeType);
                res.setHeader('Content-Disposition', `attachment; filename="${safeFilename}"`);

                res.send(report.report_down);
            } else {
                res.status(404).json({ error: '보고서 데이터가 존재하지 않습니다.' });
            }
        } catch (error) {
            console.error('보고서 데이터를 가져오는 중 오류 발생:', error);
            res.status(500).json({ error: '보고서 데이터를 가져오는 중 오류가 발생했습니다.' });
        }
    }
});

// 견적 요청 API
app.post('/estimate-request', upload.any(), async (req, res) => {
    try {
        console.log("Received files:", req.files); // 요청된 파일 로그 확인

        const {
            schoolName,
            contactPerson,
            email,
            annualVisit,
            annualFilterChange,
            details
        } = req.body;

        // 각 변수가 배열인지 확인하고, 그렇지 않다면 배열로 변환
        const equipmentArray = Array.isArray(req.body.equipment) ? req.body.equipment : [req.body.equipment];
        const manufacturersArray = Array.isArray(req.body.manufacturer) ? req.body.manufacturer : [req.body.manufacturer];
        const modelsArray = Array.isArray(req.body.model) ? req.body.model : [req.body.model];
        const quantitiesArray = Array.isArray(req.body.quantity) ? req.body.quantity : [req.body.quantity];
        let equipmentDetails = '';

        // 정보를 HTML 표 형식으로 조합
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

        // 데이터가 비어있는 경우에 대한 처리
        if (equipmentDetails === '') {
            equipmentDetails = '<tr><td colspan="5">보유 기기 정보가 유효하지 않습니다.</td></tr>';
        }

        // HTML 형식의 이메일 본문 내용 생성
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

        // 이메일 옵션 (HTML 본문 사용)
        const mailOptions = {
            from: 'seven5629@naver.com',
            to: 'miraesafeti@naver.com',
            subject: `[MOKKOJI] "${schoolName}"에서 공기순환기 통합솔루션을 통한 새 견적 요청이 접수되었습니다.`,
            html: mailText,  // HTML 형식의 이메일 본문 설정
            attachments: req.files.filter(file=>file.fieldname=='files').map(file => ({
                filename: Buffer.from(file.originalname, 'latin1').toString('utf8'),  // 파일명을 UTF-8로 변환
                content: file.buffer,
                contentType: file.mimetype
            }))
        };

        // 이메일 전송
        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error('이메일 전송 중 오류 발생:', error);
                return res.status(500).json({ success: false, message: '이메일 전송 중 오류가 발생했습니다.' });
            } else {
                console.log('이메일 전송 성공:', info.response);
                res.json({ success: true, message: '견적 요청이 성공적으로 저장되었습니다.' });
            }
        });
    } catch (error) {
        console.error('견적 요청 처리 중 오류 발생:', error);
        res.status(500).json({ success: false, message: '견적 요청 처리 중 오류가 발생했습니다.' });
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
                mediumcount, mediumsize, hepacount, hepasize, location
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                location = VALUES(location)
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
                location
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
                location
            ]);
        }

        // Step 4: sys.school 테이블 업데이트
        const today = new Date();
        const nextReplacementDate = new Date(today);
        nextReplacementDate.setMonth(today.getMonth() + 6); // 6개월 후 날짜 설정

        const formattedToday = today.toISOString().split('T')[0];
        const formattedNextReplacement = nextReplacementDate.toISOString().split('T')[0];

        // 현재 접속한 ID를 통해 NAME을 조회하여 저장
        const [userResult] = await connection.query(
            'SELECT NAME FROM sys.account WHERE ID = ?',
            [userId]
        );

        if (userResult.length === 0) {
            throw new Error('해당 사용자 ID를 찾을 수 없습니다.');
        }

        const userName = userResult[0].NAME;

        // school_info, school_md, school_nextinfo 필드 업데이트
        await connection.query(
            `UPDATE sys.school
             SET school_info = ?, school_md = ?, school_nextinfo = ?
             WHERE school_id = ?`,
            [formattedToday, userName, formattedNextReplacement, school_id]
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
// 서버 시작
app.listen(PORT, () => {
    console.log(`서버가 http://218.156.106.25:${PORT} 에서 실행 중입니다.`);
});
