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
    database: 'Mysql'
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
    const query = `
        SELECT school_id, school_name, school_grade, school_create, school_type,
               school_address1, school_address2, school_info, school_md, school_nextinfo
        FROM sys.school
        WHERE school_id = ?
    `;

    try {
        const [results] = await pool.query(query, [userFrom]);
        res.json(results);
    } catch (error) {
        console.error('학교 정보를 가져오는 중 오류 발생:', error);
        res.status(500).json({ error: '데이터를 가져오는 중 오류가 발생했습니다.' });
    }
});

// 장비 정보 조회 API
app.get('/equipmentinfo', async (req, res) => {
    const userFrom = req.query.from;
    const query = `
        SELECT eq_no, deviceType, manufacturer, modelName, precount, presize,
               mediumcount, mediumsize, hepacount, hepasize, location
        FROM sys.school_info
        WHERE school_id = ?
    `;

    try {
        const [results] = await pool.query(query, [userFrom]);
        res.json(results);
    } catch (error) {
        console.error('장비 정보를 가져오는 중 오류 발생:', error);
        res.status(500).json({ error: '장비 정보를 가져오는 중 오류가 발생했습니다.' });
    }
});

// 보고서 데이터 조회 API
app.get('/reportdata', async (req, res) => {
    const schoolId = req.query.school_id;
    const query = `
        SELECT report_no, report_down, report_date, report_filename, report_size
        FROM sys.report 
        WHERE school_id = ?
    `;

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
});

// 보고서 데이터 다운로드 API (모든 파일 확장자에 대응)
app.get('/reportdown', async (req, res) => {
    const schoolId = req.query.school_id;
    const no = req.query.no;

    const query = `
        SELECT report_date, report_filename, report_down
        FROM sys.report 
        WHERE school_id = ? AND report_no = ?
    `;

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

        const equipment = req.body.equipment;
        const manufacturers = req.body.manufacturer;
        const models = req.body.model;
        const quantities = req.body.quantity;

        // 보유 기기 정보를 HTML 표 형식으로 조합
        let equipmentDetails = '';
        if (Array.isArray(equipment) && Array.isArray(manufacturers) && Array.isArray(models) && Array.isArray(quantities)) {
            equipment.forEach((item, index) => {
                const manufacturer = manufacturers[index] || '정보 없음';
                const model = models[index] || '정보 없음';
                const quantity = quantities[index] || '정보 없음';

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
        } else {
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
            from: 'miraesafeti@naver.com',
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

// 서버 시작
app.listen(PORT, () => {
    console.log(`서버가 http://218.156.106.25:${PORT} 에서 실행 중입니다.`);
});
