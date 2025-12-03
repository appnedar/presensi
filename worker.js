// ============================================================================
// APLIKASI PRESENSI - WORKERS + D1 + R2 + PWA + PWD + DARK MODE + DASHBOARD + Admin
// Version 5.7.0 - Production Ready
// ============================================================================
//
// FITUR:
// ✅ Universal URL (auto-detect cabang)
// ✅ Login & Auth dengan D1
// ✅ Clock In/Out dengan R2 photo storage
// ✅ Buffer Attendance
// ✅ Dashboard Public (siapa saja bisa lihat)
// ✅ Dashboard Admin (login required untuk export)
// ✅ Export CSV (default) + Excel (optional)
// ✅ List "Tidak Hadir Hari Ini"
// ✅ Filter cabang & tanggal
// ✅ PWA Support
//
// DEPLOYMENT:
// 1. Bind D1 database dengan nama "DB"
// 2. Bind R2 bucket dengan nama "PHOTOS"
// 3. Deploy ke Cloudflare Workers
// 4. Setup custom domain: absen.gos.co.id
//
// ============================================================================

// ============================================================================
// SECTION 1: CONFIGURATION & MAIN HANDLER
// ============================================================================

// Admin credentials (hardcoded untuk simplicity)
const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD_HASH = 'JAvlGPq9JyTdtvBO6x2llnRI1+gxwIyPqCKAn3THIKk='; // "admin123" in SHA-256 Base64

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;

        // CORS headers
        const corsHeaders = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        };

        if (request.method === 'OPTIONS') {
            return new Response(null, { headers: corsHeaders });
        }

        try {
            // Route: Serve Photos from R2 (Fix DNS Error)
            if (path.startsWith('/photos/')) {
                return handleGetPhoto(request, env);
            }

            // Route: Halaman Absen (Clock In/Out)
            if (path === '/absen') {
                return handleAbsenPage(request, env);
            }

            // Route: Dashboard Public (All Employees)
            if (path === '/dashboard') {
                return handleDashboard(request, env);
            }

            // Route: Dashboard Employee (Individual)
            if (path === '/dashboard/employee') {
                return handleEmployeeDashboard(request, env);
            }

            // Route: Dashboard Admin Login
            if (path === '/admin/login' && request.method === 'POST') {
                return handleAdminLogin(request, env);
            }

            // Route: Export CSV
            if (path === '/admin/export/csv' && request.method === 'POST') {
                return handleExportCSV(request, env);
            }

            // Route: Export Excel
            if (path === '/admin/export/excel' && request.method === 'POST') {
                return handleExportExcel(request, env);
            }

            // Route: API - Login
            if (path === '/api/login' && request.method === 'POST') {
                return handleLogin(request, env);
            }

            // Route: API - Login Buffer
            if (path === '/api/login-buffer' && request.method === 'POST') {
                return handleLoginBuffer(request, env);
            }

            // Route: API - Get Karyawan (for buffer search)
            if (path === '/api/karyawan' && request.method === 'GET') {
                return handleGetKaryawan(request, env);
            }

            // Route: API - Get Status
            if (path === '/api/status' && request.method === 'GET') {
                return handleGetStatus(request, env);
            }

            // Route: API - Clock In
            if (path === '/api/clockin' && request.method === 'POST') {
                return handleClockIn(request, env);
            }

            // Route: API - Clock Out
            if (path === '/api/clockout' && request.method === 'POST') {
                return handleClockOut(request, env);
            }

            // Route: API - Change Password
            if (path === '/api/change-password' && request.method === 'POST') {
                return handleChangePassword(request, env);
            }

            // Route: Change Password Page
            if (path === '/change-password') {
                return handleChangePasswordPage(request, env);
            }

            // Route: API - Report Today
            if (path === '/api/report/today' && request.method === 'GET') {
                return handleReportToday(request, env);
            }

            // Route: API - Report Weekly
            if (path === '/api/report/weekly' && request.method === 'GET') {
                return handleReportWeekly(request, env);
            }

            // Route: API - Report Monthly
            if (path === '/api/report/monthly' && request.method === 'GET') {
                return handleReportMonthly(request, env);
            }

            // Route: API - Report Employee Daily
            if (path === '/api/report/employee/daily' && request.method === 'GET') {
                return handleReportEmployeeDaily(request, env);
            }

            // Route: API - Report Employee Weekly
            if (path === '/api/report/employee/weekly' && request.method === 'GET') {
                return handleReportEmployeeWeekly(request, env);
            }

            // Route: API - Report Employee Monthly
            if (path === '/api/report/employee/monthly' && request.method === 'GET') {
                return handleReportEmployeeMonthly(request, env);
            }

            // Route: API - Report Tidak Hadir
            if (path === '/api/report/tidak-hadir' && request.method === 'GET') {
                return handleReportTidakHadir(request, env);
            }

            // Route: PWA Manifest
            if (path === '/manifest.json') {
                return new Response(getManifest(), {
                    headers: { 'Content-Type': 'application/json', ...corsHeaders }
                });
            }

            // Route: Admin Panel Page (UI for export)
            if (path === '/admin-panel') {
                return handleAdminPanel(request, env);
            }

            // Route: Service Worker
            if (path === '/sw.js') {
                return new Response(getServiceWorker(), {
                    headers: { 'Content-Type': 'application/javascript', ...corsHeaders }
                });
            }

            // Route: Main Page (Login)
            if (path === '/' || path === '/index.html') {
                return new Response(getLoginHTML(), {
                    headers: { 'Content-Type': 'text/html', ...corsHeaders }
                });
            }

            return new Response('Not Found', { status: 404, headers: corsHeaders });

        } catch (error) {
            console.error('Error:', error);
            return jsonResponse({ error: error.message }, 500, corsHeaders);
        }
    }
};

// Helper to serve photos
async function handleGetPhoto(request, env) {
    const url = new URL(request.url);
    const key = url.pathname.replace('/photos/', '');

    const object = await env.PHOTOS.get(key);
    if (!object) {
        return new Response('Photo not found', { status: 404 });
    }

    const headers = new Headers();
    object.writeHttpMetadata(headers);
    headers.set('etag', object.httpEtag);

    return new Response(object.body, { headers });
}

async function handleAbsenPage(request, env) {
    const html = getAbsenHTML();
    return new Response(html, {
        headers: { 'Content-Type': 'text/html' }
    });
}

// ============================================================================
// SECTION 2: HELPER FUNCTIONS
// ============================================================================

function jsonResponse(data, status = 200, additionalHeaders = {}) {
    return new Response(JSON.stringify(data), {
        status,
        headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            ...additionalHeaders
        }
    });
}

async function hashPassword(text) {
    const msgBuffer = new TextEncoder().encode(text);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    return btoa(String.fromCharCode(...new Uint8Array(hashBuffer)));
}

async function handleChangePasswordPage(request, env) {
    const html = getChangePasswordHTML();
    return new Response(html, {
        headers: { 'Content-Type': 'text/html' }
    });
}

function getLocalTimestamp() {
    const now = new Date();
    const offset = 7 * 60 * 60 * 1000; // UTC+7
    const localTime = new Date(now.getTime() + offset);
    return localTime.toISOString().replace('T', ' ').substring(0, 19);
}

function getTodayDate() {
    const now = new Date();
    const offset = 7 * 60 * 60 * 1000;
    const localTime = new Date(now.getTime() + offset);
    return localTime.toISOString().split('T')[0];
}

function calculateDistance(lat1, lon1, lat2, lon2) {
    const R = 6371e3; // Earth radius in meters
    const φ1 = lat1 * Math.PI / 180;
    const φ2 = lat2 * Math.PI / 180;
    const Δφ = (lat2 - lat1) * Math.PI / 180;
    const Δλ = (lon2 - lon1) * Math.PI / 180;
    const a = Math.sin(Δφ / 2) * Math.sin(Δφ / 2) +
        Math.cos(φ1) * Math.cos(φ2) *
        Math.sin(Δλ / 2) * Math.sin(Δλ / 2);
    return Math.round(R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a)));
}

// ============================================================================
// SECTION 3: AUTHENTICATION FUNCTIONS
// ============================================================================

async function handleLogin(request, env) {
    try {
        const body = await request.json();
        const { nik, password } = body;

        if (!nik || !password) {
            return jsonResponse({ error: 'NIK dan Password harus diisi' }, 400);
        }

        // Hash password
        const passwordHash = await hashPassword(password);

        // Query karyawan
        const karyawan = await env.DB.prepare(`
            SELECT k.*, c.latitude, c.longitude
            FROM karyawan k
            JOIN cabang c ON k.stock_point = c.stock_point
            WHERE k.nik = ? AND k.password_hash = ? AND k.status = 1
        `).bind(nik, passwordHash).first();

        if (!karyawan) {
            return jsonResponse({ error: 'NIK atau Password salah, atau akun tidak aktif' }, 401);
        }

        return jsonResponse({
            success: true,
            user: {
                nik: karyawan.nik,
                nama: karyawan.nama,
                shift: karyawan.shift,
                jabatan: karyawan.jabatan,
                stockPoint: karyawan.stock_point,
                cabang: karyawan.cabang,
                cabangLokasi: `${karyawan.latitude},${karyawan.longitude}`
            }
        });

    } catch (error) {
        return jsonResponse({ error: error.message }, 500);
    }
}

async function handleLoginBuffer(request, env) {
    try {
        const body = await request.json();
        const { nikKtp, namaBuffer, karyawanNik } = body;

        if (!nikKtp || !namaBuffer || !karyawanNik) {
            return jsonResponse({ error: 'Semua field harus diisi' }, 400);
        }

        // Query karyawan yang digantikan
        const karyawan = await env.DB.prepare(`
            SELECT k.*, c.latitude, c.longitude
            FROM karyawan k
            LEFT JOIN cabang c ON k.stock_point = c.stock_point
            WHERE k.nik = ? AND k.status = 1
        `).bind(karyawanNik).first();

        if (!karyawan) {
            return jsonResponse({ error: 'Karyawan tidak ditemukan atau tidak aktif' }, 404);
        }

        return jsonResponse({
            success: true,
            buffer: {
                nikKtp: nikKtp,
                namaBuffer: namaBuffer,
                karyawanNik: karyawan.nik,
                karyawanNama: karyawan.nama,
                shift: karyawan.shift || '-',
                stockPoint: karyawan.stock_point || 'Unknown',
                cabang: karyawan.cabang || 'Unknown',
                cabangLokasi: karyawan.latitude ? `${karyawan.latitude},${karyawan.longitude}` : '0,0',
                isBuffer: true
            }
        });

    } catch (error) {
        return jsonResponse({ error: error.message }, 500);
    }
}

async function handleAdminLogin(request, env) {
    try {
        const body = await request.json();
        const { username, password } = body;

        const passwordHash = await hashPassword(password);

        if (username === ADMIN_USERNAME && passwordHash === ADMIN_PASSWORD_HASH) {
            // Generate simple token (in production, use JWT)
            const token = btoa(`${username}:${Date.now()}`);
            return jsonResponse({ success: true, token });
        }

        return jsonResponse({ error: 'Username atau password salah' }, 401);

    } catch (error) {
        return jsonResponse({ error: error.message }, 500);
    }
}

async function handleChangePassword(request, env) {
    try {
        const body = await request.json();
        const { nik, oldPassword, newPassword } = body;

        if (!nik || !oldPassword || !newPassword) {
            return jsonResponse({ error: 'Semua field harus diisi' }, 400);
        }

        if (newPassword.length < 6) {
            return jsonResponse({ error: 'Password baru minimal 6 karakter' }, 400);
        }

        const oldHash = await hashPassword(oldPassword);
        const newHash = await hashPassword(newPassword);

        // Verify old password
        const karyawan = await env.DB.prepare(`
            SELECT nik FROM karyawan WHERE nik = ? AND password_hash = ?
        `).bind(nik, oldHash).first();

        if (!karyawan) {
            return jsonResponse({ error: 'Password lama salah' }, 400);
        }

        // Update password
        await env.DB.prepare(`
            UPDATE karyawan SET password_hash = ?, updated_at = CURRENT_TIMESTAMP
            WHERE nik = ?
        `).bind(newHash, nik).run();

        return jsonResponse({ success: true });

    } catch (error) {
        return jsonResponse({ error: error.message }, 500);
    }
}

// ============================================================================
// SECTION 4: ATTENDANCE FUNCTIONS (D1 + R2)
// ============================================================================

async function handleGetKaryawan(request, env) {
    try {
        const url = new URL(request.url);
        const cabang = url.searchParams.get('cabang');

        let query = `
            SELECT nik, nama, shift, stock_point, cabang
            FROM karyawan
            WHERE status = 1
        `;

        if (cabang) {
            query += ` AND cabang = ?`;
            const result = await env.DB.prepare(query).bind(cabang).all();
            return jsonResponse({ karyawan: result.results || [] });
        } else {
            const result = await env.DB.prepare(query).all();
            return jsonResponse({ karyawan: result.results || [] });
        }

    } catch (error) {
        return jsonResponse({ error: error.message }, 500);
    }
}

async function handleGetStatus(request, env) {
    try {
        const url = new URL(request.url);
        const nik = url.searchParams.get('nik');
        const nikKtp = url.searchParams.get('nikKtp');
        const isBuffer = url.searchParams.get('isBuffer') === 'true';
        const today = getTodayDate();

        if (isBuffer && nikKtp) {
            // Check buffer attendance
            const absen = await env.DB.prepare(`
                SELECT * FROM absensi_buffer
                WHERE tanggal = ? AND nik_ktp = ?
            `).bind(today, nikKtp).first();

            return jsonResponse({
                clockIn: absen?.time_in || null,
                clockOut: absen?.time_out || null,
                durasi: absen?.durasi_text || null
            });
        } else {
            // Check normal attendance
            const absen = await env.DB.prepare(`
                SELECT * FROM absensi
                WHERE tanggal = ? AND nik = ?
            `).bind(today, nik).first();

            return jsonResponse({
                clockIn: absen?.time_in || null,
                clockOut: absen?.time_out || null,
                durasi: absen?.durasi_text || null
            });
        }

    } catch (error) {
        return jsonResponse({ error: error.message }, 500);
    }
}

async function handleClockIn(request, env) {
    try {
        const body = await request.json();
        const { nik, nama, stockPoint, lat, lng, photoBase64, jarak, isBuffer, nikKtp, namaBuffer, karyawanNama, karyawanNik } = body;
        const today = getTodayDate();
        const now = getLocalTimestamp();
        const url = new URL(request.url); // Get current worker URL

        // Upload photo to R2
        const photoKey = isBuffer
            ? `buffer/${today}/IN_${nikKtp}_${Date.now()}.jpg`
            : `normal/${today}/IN_${nik}_${Date.now()}.jpg`;

        const photoData = photoBase64.split(',')[1]; // Remove data:image/jpeg;base64,
        const photoBuffer = Uint8Array.from(atob(photoData), c => c.charCodeAt(0));

        await env.PHOTOS.put(photoKey, photoBuffer, {
            httpMetadata: { contentType: 'image/jpeg' }
        });

        // Use Worker URL to serve photo
        const photoUrl = `${url.origin}/photos/${photoKey}`;

        if (isBuffer) {
            // Check duplicate
            const existing = await env.DB.prepare(`
                SELECT id FROM absensi_buffer WHERE tanggal = ? AND nik_ktp = ?
            `).bind(today, nikKtp).first();

            if (existing) {
                return jsonResponse({ error: 'NIK KTP sudah absen hari ini' }, 400);
            }

            // Get cabang (Fix undefined error)
            // Use karyawanNik for buffer query
            const targetNik = karyawanNik || nik;

            const karyawanData = await env.DB.prepare(`
                SELECT cabang FROM karyawan WHERE nik = ?
            `).bind(targetNik).first();

            const cabangName = karyawanData ? karyawanData.cabang : 'Unknown';

            // Insert buffer attendance
            await env.DB.prepare(`
                INSERT INTO absensi_buffer 
                (tanggal, nik_ktp, nama_buffer, nik_oms, karyawan_digantikan, cabang, stock_point,
                 time_in, lokasi_in_lat, lokasi_in_lng, lokasi_in_url, jarak_in, photo_in_url)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `).bind(
                today, nikKtp, namaBuffer, targetNik, karyawanNama, cabangName, stockPoint || 'Unknown',
                now, lat, lng, `https://www.google.com/maps?q=${lat},${lng}`, jarak, photoUrl
            ).run();

        } else {
            // Check duplicate
            const existing = await env.DB.prepare(`
                SELECT id FROM absensi WHERE tanggal = ? AND nik = ?
            `).bind(today, nik).first();

            if (existing) {
                return jsonResponse({ error: 'Anda sudah Absen Masuk hari ini' }, 400);
            }

            // Get cabang (Fix undefined error)
            const karyawanData = await env.DB.prepare(`
                SELECT cabang FROM karyawan WHERE nik = ?
            `).bind(nik).first();

            const cabangName = karyawanData ? karyawanData.cabang : 'Unknown';

            // Insert normal attendance
            await env.DB.prepare(`
                INSERT INTO absensi 
                (tanggal, nik, nama, cabang, stock_point,
                 time_in, lokasi_in_lat, lokasi_in_lng, lokasi_in_url, jarak_in, photo_in_url)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `).bind(
                today, nik, nama, cabangName, stockPoint || 'Unknown',
                now, lat, lng, `https://www.google.com/maps?q=${lat},${lng}`, jarak, photoUrl
            ).run();
        }

        return jsonResponse({ success: true, time: now });

    } catch (error) {
        console.error('Clock In Error:', error);
        return jsonResponse({ error: error.message }, 500);
    }
}

async function handleClockOut(request, env) {
    try {
        const body = await request.json();
        const { nik, lat, lng, photoBase64, jarak, isBuffer, nikKtp } = body;
        const today = getTodayDate();
        const now = getLocalTimestamp();
        const url = new URL(request.url);

        // Upload photo to R2
        const photoKey = isBuffer
            ? `buffer/${today}/OUT_${nikKtp}_${Date.now()}.jpg`
            : `normal/${today}/OUT_${nik}_${Date.now()}.jpg`;

        const photoData = photoBase64.split(',')[1];
        const photoBuffer = Uint8Array.from(atob(photoData), c => c.charCodeAt(0));

        await env.PHOTOS.put(photoKey, photoBuffer, {
            httpMetadata: { contentType: 'image/jpeg' }
        });

        const photoUrl = `${url.origin}/photos/${photoKey}`;

        if (isBuffer) {
            // Get existing record
            const absen = await env.DB.prepare(`
                SELECT * FROM absensi_buffer WHERE tanggal = ? AND nik_ktp = ?
            `).bind(today, nikKtp).first();

            if (!absen) {
                return jsonResponse({ error: 'Belum Absen Masuk hari ini' }, 400);
            }

            if (absen.time_out) {
                return jsonResponse({ error: 'Sudah Absen Pulang hari ini' }, 400);
            }

            // Calculate duration
            const timeIn = new Date(absen.time_in.replace(' ', 'T'));
            const timeOut = new Date(now.replace(' ', 'T'));
            const durasiMenit = Math.round((timeOut - timeIn) / 60000);
            const jam = Math.floor(durasiMenit / 60);
            const menit = durasiMenit % 60;
            const durasiText = `${jam} jam ${menit} menit`;

            // Update record
            await env.DB.prepare(`
                UPDATE absensi_buffer SET
                time_out = ?, lokasi_out_lat = ?, lokasi_out_lng = ?, lokasi_out_url = ?,
                jarak_out = ?, photo_out_url = ?, durasi_menit = ?, durasi_text = ?,
                updated_at = CURRENT_TIMESTAMP
                WHERE tanggal = ? AND nik_ktp = ?
            `).bind(
                now, lat, lng, `https://www.google.com/maps?q=${lat},${lng}`,
                jarak, photoUrl, durasiMenit, durasiText, today, nikKtp
            ).run();

            return jsonResponse({ success: true, time: now, durasi: durasiText });

        } else {
            // Get existing record
            const absen = await env.DB.prepare(`
                SELECT * FROM absensi WHERE tanggal = ? AND nik = ?
            `).bind(today, nik).first();

            if (!absen) {
                return jsonResponse({ error: 'Belum Absen Masuk hari ini' }, 400);
            }

            if (absen.time_out) {
                return jsonResponse({ error: 'Sudah Absen Pulang hari ini' }, 400);
            }

            // Calculate duration
            const timeIn = new Date(absen.time_in.replace(' ', 'T'));
            const timeOut = new Date(now.replace(' ', 'T'));
            const durasiMenit = Math.round((timeOut - timeIn) / 60000);
            const jam = Math.floor(durasiMenit / 60);
            const menit = durasiMenit % 60;
            const durasiText = `${jam} jam ${menit} menit`;

            // Update record
            await env.DB.prepare(`
                UPDATE absensi SET
                time_out = ?, lokasi_out_lat = ?, lokasi_out_lng = ?, lokasi_out_url = ?,
                jarak_out = ?, photo_out_url = ?, durasi_menit = ?, durasi_text = ?,
                updated_at = CURRENT_TIMESTAMP
                WHERE tanggal = ? AND nik = ?
            `).bind(
                now, lat, lng, `https://www.google.com/maps?q=${lat},${lng}`,
                jarak, photoUrl, durasiMenit, durasiText, today, nik
            ).run();

            return jsonResponse({ success: true, time: now, durasi: durasiText });
        }

    } catch (error) {
        console.error('Absen Pulang Error:', error);
        return jsonResponse({ error: error.message }, 500);
    }
}

// ============================================================================
// SECTION 5: REPORTING API FUNCTIONS
// ============================================================================

async function handleReportToday(request, env) {
    try {
        const url = new URL(request.url);
        const cabang = url.searchParams.get('cabang');
        const today = getTodayDate();

        let query = `
            SELECT 
                COUNT(DISTINCT nik) as total_hadir,
                COUNT(CASE WHEN time_out IS NOT NULL THEN 1 END) as sudah_pulang,
                COUNT(CASE WHEN time_out IS NULL THEN 1 END) as belum_pulang
            FROM absensi 
            WHERE tanggal = ?
        `;

        const params = [today];

        if (cabang) {
            query += ` AND cabang = ?`;
            params.push(cabang);
        }

        const result = await env.DB.prepare(query).bind(...params).first();

        return jsonResponse(result || { total_hadir: 0, sudah_pulang: 0, belum_pulang: 0 });

    } catch (error) {
        return jsonResponse({ error: error.message }, 500);
    }
}

async function handleReportWeekly(request, env) {
    try {
        const url = new URL(request.url);
        const cabang = url.searchParams.get('cabang');

        let query = `
            SELECT 
                tanggal,
                COUNT(DISTINCT nik) as total_hadir
            FROM absensi 
            WHERE tanggal >= DATE('now', '-7 days', '+7 hours')
        `;

        if (cabang) {
            query += ` AND cabang = ?`;
        }

        query += ` GROUP BY tanggal ORDER BY tanggal DESC`;

        const result = cabang
            ? await env.DB.prepare(query).bind(cabang).all()
            : await env.DB.prepare(query).all();

        return jsonResponse({ data: result.results || [] });

    } catch (error) {
        return jsonResponse({ error: error.message }, 500);
    }
}

async function handleReportMonthly(request, env) {
    try {
        const url = new URL(request.url);
        const cabang = url.searchParams.get('cabang');
        const bulan = url.searchParams.get('bulan') || getTodayDate().substring(0, 7); // YYYY-MM
        const page = Math.max(1, parseInt(url.searchParams.get('page') || '1', 10));
        const pageSize = Math.min(100, Math.max(1, parseInt(url.searchParams.get('pageSize') || '20', 10)));

        let countQuery = `
            SELECT COUNT(DISTINCT k.nik) as total
            FROM karyawan k
            LEFT JOIN absensi a ON k.nik = a.nik 
                AND a.tanggal LIKE ?
            WHERE k.status = 1
        `;

        let dataQuery = `
            SELECT 
                k.nik,
                k.nama,
                k.cabang,
                COUNT(a.id) as total_hadir,
                COUNT(CASE WHEN a.time_out IS NOT NULL THEN 1 END) as lengkap,
                AVG(a.durasi_menit) as avg_durasi_menit
            FROM karyawan k
            LEFT JOIN absensi a ON k.nik = a.nik 
                AND a.tanggal LIKE ?
            WHERE k.status = 1
        `;

        const params = [`${bulan}%`];

        if (cabang) {
            countQuery += ` AND k.cabang = ?`;
            dataQuery += ` AND k.cabang = ?`;
            params.push(cabang);
        }

        // Get total count
        const countResult = await env.DB.prepare(countQuery).bind(...params).first();
        const total = countResult?.total || 0;

        dataQuery += ` GROUP BY k.nik, k.nama, k.cabang ORDER BY total_hadir DESC LIMIT ? OFFSET ?`;

        // Get paginated data
        const offset = (page - 1) * pageSize;
        const result = await env.DB.prepare(dataQuery).bind(...params, pageSize, offset).all();

        return jsonResponse({ data: result.results || [], total: total });

    } catch (error) {
        return jsonResponse({ error: error.message }, 500);
    }
}

async function handleReportTidakHadir(request, env) {
    try {
        const url = new URL(request.url);
        const cabang = url.searchParams.get('cabang');
        const tanggal = url.searchParams.get('tanggal') || getTodayDate();
        const page = Math.max(1, parseInt(url.searchParams.get('page') || '1', 10));
        const pageSize = Math.min(100, Math.max(1, parseInt(url.searchParams.get('pageSize') || '20', 10)));

        let countQuery = `
            SELECT COUNT(*) as total FROM karyawan k
            WHERE k.status = 1
            AND k.nik NOT IN (
                SELECT nik FROM absensi WHERE tanggal = ?
            )
        `;

        let dataQuery = `
            SELECT k.nik, k.nama, k.cabang, k.shift
            FROM karyawan k
            WHERE k.status = 1
            AND k.nik NOT IN (
                SELECT nik FROM absensi WHERE tanggal = ?
            )
        `;

        const params = [tanggal];

        if (cabang) {
            countQuery += ` AND k.cabang = ?`;
            dataQuery += ` AND k.cabang = ?`;
            params.push(cabang);
        }

        dataQuery += ` ORDER BY k.cabang, k.nama LIMIT ? OFFSET ?`;

        // Get total count
        const countResult = await env.DB.prepare(countQuery).bind(...params).first();
        const total = countResult?.total || 0;

        // Get paginated data
        const offset = (page - 1) * pageSize;
        const result = await env.DB.prepare(dataQuery).bind(...params, pageSize, offset).all();

        return jsonResponse({ data: result.results || [], total: total });

    } catch (error) {
        return jsonResponse({ error: error.message }, 500);
    }
}

// ============================================================================
// SECTION 5B: EMPLOYEE-SPECIFIC REPORTING API FUNCTIONS
// ============================================================================

async function handleReportEmployeeDaily(request, env) {
    try {
        const url = new URL(request.url);
        const nik = url.searchParams.get('nik');
        const tanggal = url.searchParams.get('tanggal') || getTodayDate();

        if (!nik) {
            return jsonResponse({ error: 'NIK required' }, 400);
        }

        // Get attendance for specific date
        const absen = await env.DB.prepare(`
            SELECT 
                tanggal, nik, nama, cabang, stock_point,
                time_in, lokasi_in_lat, lokasi_in_lng, jarak_in, photo_in_url,
                time_out, lokasi_out_lat, lokasi_out_lng, jarak_out, photo_out_url,
                durasi_menit, durasi_text
            FROM absensi
            WHERE nik = ? AND tanggal = ?
        `).bind(nik, tanggal).first();

        return jsonResponse({
            data: absen || null,
            tanggal: tanggal
        });

    } catch (error) {
        return jsonResponse({ error: error.message }, 500);
    }
}

async function handleReportEmployeeWeekly(request, env) {
    try {
        const url = new URL(request.url);
        const nik = url.searchParams.get('nik');

        if (!nik) {
            return jsonResponse({ error: 'NIK required' }, 400);
        }

        // Get last 7 days attendance
        const result = await env.DB.prepare(`
            SELECT 
                tanggal, time_in, time_out, durasi_text, jarak_in, jarak_out
            FROM absensi
            WHERE nik = ? 
            AND tanggal >= DATE('now', '-7 days', '+7 hours')
            ORDER BY tanggal DESC
        `).bind(nik).all();

        return jsonResponse({ data: result.results || [] });

    } catch (error) {
        return jsonResponse({ error: error.message }, 500);
    }
}

async function handleReportEmployeeMonthly(request, env) {
    try {
        const url = new URL(request.url);
        const nik = url.searchParams.get('nik');
        const bulan = url.searchParams.get('bulan') || getTodayDate().substring(0, 7); // YYYY-MM

        if (!nik) {
            return jsonResponse({ error: 'NIK required' }, 400);
        }

        // Get monthly attendance
        const result = await env.DB.prepare(`
            SELECT 
                tanggal, time_in, time_out, durasi_text, durasi_menit,
                jarak_in, jarak_out, photo_in_url, photo_out_url
            FROM absensi
            WHERE nik = ? AND tanggal LIKE ?
            ORDER BY tanggal DESC
        `).bind(nik, `${bulan}%`).all();

        // Calculate statistics
        const data = result.results || [];
        const totalHadir = data.length;
        const lengkap = data.filter(d => d.time_out).length;
        const totalDurasi = data.reduce((sum, d) => sum + (d.durasi_menit || 0), 0);
        const avgDurasi = totalHadir > 0 ? Math.round(totalDurasi / totalHadir) : 0;

        return jsonResponse({
            data: data,
            summary: {
                bulan: bulan,
                total_hadir: totalHadir,
                lengkap: lengkap,
                avg_durasi_menit: avgDurasi,
                avg_durasi_jam: Math.round(avgDurasi / 60)
            }
        });

    } catch (error) {
        return jsonResponse({ error: error.message }, 500);
    }
}

// ============================================================================
// SECTION 6: EXPORT FUNCTIONS
// ============================================================================

async function handleExportCSV(request, env) {
    try {
        const body = await request.json();
        const { cabang, startDate, endDate, token } = body;

        // Verify admin token (simple check)
        if (!token) {
            return jsonResponse({ error: 'Unauthorized' }, 401);
        }

        let query = `
            SELECT 
                tanggal, nik, nama, cabang, stock_point,
                time_in, jarak_in, time_out, jarak_out, durasi_text
            FROM absensi
            WHERE 1=1
        `;

        const params = [];

        if (cabang) {
            query += ` AND cabang = ?`;
            params.push(cabang);
        }

        if (startDate) {
            query += ` AND tanggal >= ?`;
            params.push(startDate);
        }

        if (endDate) {
            query += ` AND tanggal <= ?`;
            params.push(endDate);
        }

        query += ` ORDER BY tanggal DESC, cabang, nama`;

        const result = await env.DB.prepare(query).bind(...params).all();
        const data = result.results || [];

        // Generate CSV
        const headers = ['Tanggal', 'NIK', 'Nama', 'Cabang', 'Stock Point', 'Absen Masuk', 'Jarak In (m)', 'Absen Keluar', 'Jarak Out (m)', 'Durasi'];
        const rows = data.map(row => [
            row.tanggal,
            row.nik,
            row.nama,
            row.cabang,
            row.stock_point,
            row.time_in || '-',
            row.jarak_in || '-',
            row.time_out || '-',
            row.jarak_out || '-',
            row.durasi_text || '-'
        ]);

        const csv = [
            headers.join(','),
            ...rows.map(row => row.map(cell => `"${cell}"`).join(','))
        ].join('\n');

        return new Response(csv, {
            headers: {
                'Content-Type': 'text/csv',
                'Content-Disposition': `attachment; filename="absensi-${getTodayDate()}.csv"`
            }
        });

    } catch (error) {
        return jsonResponse({ error: error.message }, 500);
    }
}

async function handleExportExcel(request, env) {
    // For Excel export, we'll return JSON that frontend can convert to Excel using SheetJS
    try {
        const body = await request.json();
        const { cabang, startDate, endDate, token } = body;

        if (!token) {
            return jsonResponse({ error: 'Unauthorized' }, 401);
        }

        let query = `
            SELECT 
                tanggal, nik, nama, cabang, stock_point,
                time_in, jarak_in, time_out, jarak_out, durasi_text
            FROM absensi
            WHERE 1=1
        `;

        const params = [];

        if (cabang) {
            query += ` AND cabang = ?`;
            params.push(cabang);
        }

        if (startDate) {
            query += ` AND tanggal >= ?`;
            params.push(startDate);
        }

        if (endDate) {
            query += ` AND tanggal <= ?`;
            params.push(endDate);
        }

        query += ` ORDER BY tanggal DESC, cabang, nama`;

        const result = await env.DB.prepare(query).bind(...params).all();

        return jsonResponse({
            data: result.results || [],
            filename: `absensi-${getTodayDate()}.xlsx`
        });

    } catch (error) {
        return jsonResponse({ error: error.message }, 500);
    }
}

// ============================================================================
// SECTION 7: DASHBOARD HTML
// ============================================================================

async function handleDashboard(request, env) {
    const html = getDashboardHTML();
    return new Response(html, {
        headers: { 'Content-Type': 'text/html' }
    });
}

async function handleEmployeeDashboard(request, env) {
    const html = getEmployeeDashboardHTML();
    return new Response(html, {
        headers: { 'Content-Type': 'text/html' }
    });
}

function getDashboardHTML() {
    return `<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard Presensi</title>
    <style>
        :root {
            color-scheme: light;
        }
        [data-theme="dark"] {
            color-scheme: dark;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
            color: #1f2937;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        .header {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        .header h1 { color: #667eea; margin-bottom: 10px; }
        .filters {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }
        .filters select, .filters input, .filters button {
            padding: 12px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            font-size: 14px;
        }
        .filters button {
            background: #667eea;
            color: white;
            border: none;
            cursor: pointer;
            font-weight: 600;
            transition: 0.3s;
        }
        .filters button:hover { background: #5568d3; }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
        }
        .stat-card h3 { color: #666; font-size: 14px; margin-bottom: 10px; }
        .stat-card .number { font-size: 36px; font-weight: bold; color: #667eea; }
        .stat-card .percentage { color: #10b981; font-size: 14px; margin-top: 5px; }
        .table-container {
            background: white;
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            overflow-x: auto;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e0e0e0;
        }
        th {
            background: #f8f9fa;
            font-weight: 600;
            color: #667eea;
        }
        tr:hover { background: #f8f9fa; }
        .badge {
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
        }
        .badge-success { background: #d1fae5; color: #065f46; }
        .badge-warning { background: #fef3c7; color: #92400e; }
        .badge-danger { background: #fee2e2; color: #991b1b; }
        .admin-section {
            background: white;
            padding: 25px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        .admin-login {
            display: grid;
            grid-template-columns: 1fr 1fr auto;
            gap: 10px;
            max-width: 600px;
        }
        .export-buttons {
            display: flex;
            gap: 10px;
            margin-top: 15px;
        }
        .export-buttons button {
            padding: 10px 20px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
            transition: 0.3s;
        }
        .btn-csv { background: #10b981; color: white; }
        .btn-csv:hover { background: #059669; }
        .btn-excel { background: #3b82f6; color: white; }
        .btn-excel:hover { background: #2563eb; }
        .hidden { display: none; }
        .loading { opacity: 0.5; pointer-events: none; }
        .spinner {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid rgba(102, 126, 234, 0.3);
            border-radius: 50%;
            border-top-color: #667eea;
            animation: spin 0.8s linear infinite;
        }
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        .error-message { color: #ef4444; margin: 10px 0; font-size: 14px; }
        .success-message { color: #10b981; margin: 10px 0; font-size: 14px; }
        .theme-toggle {
            position: fixed;
            top: 20px;
            right: 20px;
            width: 48px;
            height: 48px;
            border-radius: 50%;
            border: none;
            background: white;
            box-shadow: 0 12px 30px rgba(0,0,0,0.15);
            cursor: pointer;
            font-size: 20px;
            z-index: 1000;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }
        .theme-toggle:hover {
            transform: scale(1.05);
            box-shadow: 0 15px 35px rgba(0,0,0,0.2);
        }
        .theme-toggle:active {
            transform: scale(0.95);
        }
        [data-theme="dark"] body {
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #e2e8f0;
        }
        [data-theme="dark"] .header,
        [data-theme="dark"] .stat-card,
        [data-theme="dark"] .table-container,
        [data-theme="dark"] .admin-section {
            background: #1f2937;
            color: #e2e8f0;
            box-shadow: 0 10px 30px rgba(0,0,0,0.5);
        }
        [data-theme="dark"] .header h1 { color: #a5b4fc; }
        [data-theme="dark"] .filters select,
        [data-theme="dark"] .filters input {
            background: #0f172a;
            border-color: #334155;
            color: #e2e8f0;
        }
        [data-theme="dark"] .filters button {
            border: none;
        }
        [data-theme="dark"] table {
            color: #f8fafc;
        }
        [data-theme="dark"] th {
            background: #0f172a;
            color: #cbd5f5;
        }
        [data-theme="dark"] tr:hover { background: #0f172a; }
        [data-theme="dark"] .admin-login input {
            background: #0f172a;
            border-color: #334155;
            color: #e2e8f0;
        }
        [data-theme="dark"] .export-buttons button {
            color: #f8fafc;
        }
        [data-theme="dark"] .btn-csv { background: #059669; }
        [data-theme="dark"] .btn-excel { background: #1d4ed8; }
        [data-theme="dark"] .badge-success { background: #064e3b; color: #6ee7b7; }
        [data-theme="dark"] .badge-warning { background: #78350f; color: #fcd34d; }
        [data-theme="dark"] .badge-danger { background: #7f1d1d; color: #fecaca; }
        /* ===== RESPONSIVE MOBILE FIXES ===== */
        @media (max-width: 768px) {
            body { padding: 12px; }
            .container { max-width: 100%; }
            .header { padding: 16px; margin-bottom: 16px; }
            .header h1 { font-size: 20px; margin-bottom: 8px; }
            .header p { font-size: 12px; }
            .filters { grid-template-columns: 1fr; gap: 10px; }
            .filters select, .filters input, .filters button { width: 100%; padding: 10px; font-size: 14px; }
            .stats { grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 16px; }
            .stat-card { padding: 14px; }
            .stat-card h3 { font-size: 12px; }
            .stat-card .number { font-size: 24px; }
            .table-container { padding: 14px; margin-bottom: 14px; overflow-x: auto; -webkit-overflow-scrolling: touch; }
            .table-container h3 { font-size: 14px; margin-bottom: 10px; }
            table { width: 100%; display: block; }
            thead { display: none; }
            tbody { display: block; }
            tr { display: block; margin-bottom: 12px; border-radius: 8px; background: #fafafa; padding: 10px; border: 1px solid #e0e0e0; }
            td { display: block; padding: 6px 0; border: none; text-align: left; }
            td:before { content: attr(data-label); font-weight: 700; color: #667eea; display: inline-block; width: 90px; margin-right: 10px; }
            button[style*="padding:8px 10px"] { padding: 10px 8px; font-size: 12px; flex: 1; }
            select[id*="PageSize"] { width: 60px; }
            [data-theme="dark"] tr { background: #2a3f5f; border-color: #334155; }
            [data-theme="dark"] td:before { color: #a5b4fc; }
        }
        @media (max-width: 480px) {
            .header { padding: 12px; }
            .header h1 { font-size: 18px; }
            .stat-card .number { font-size: 20px; }
            .stats { grid-template-columns: 1fr; }
            td:before { width: 70px; font-size: 12px; }
        }
    </style>
</head>
<body>
    <button class="theme-toggle" id="themeToggle" onclick="toggleTheme()">🌙</button>
    <div class="container">
        <div class="header">
            <h1>📊 Dashboard Presensi</h1>
            <p style="color: #666; margin-top: 5px;">Real-time monitoring kehadiran karyawan</p>
            
            <div class="filters">
                <select id="filterCabang">
                    <option value="">Semua Cabang</option>
                </select>
                <input type="date" id="filterTanggal" />
                <button onclick="debounceLoadDashboard()">🔍 Filter</button>
                <button onclick="resetFilter()">🔄 Reset</button>
            </div>
        </div>

        <!-- Top Actions: Back to Login & Admin Panel -->
        <div style="display:flex; gap:12px; align-items:center; margin: 18px 0;">
            <a href="/" style="display:inline-block; padding:10px 14px; background:#f3f4f6; color:#667eea; text-decoration:none; border-radius:8px; font-weight:600;">← Kembali ke Login</a>
            <a href="/admin-panel" style="display:inline-block; padding:10px 14px; background:#fef3c7; color:#92400e; text-decoration:none; border-radius:8px; font-weight:700;">🔐 Admin</a>
        </div>

        <!-- Stats Cards -->
        <div class="stats">
            <div class="stat-card">
                <h3>Total Karyawan</h3>
                <div class="number" id="totalKaryawan">-</div>
            </div>
            <div class="stat-card">
                <h3>Hadir Hari Ini</h3>
                <div class="number" id="hadirHariIni">-</div>
                <div class="percentage" id="persentaseHadir">-</div>
            </div>
            <div class="stat-card">
                <h3>Sudah Pulang</h3>
                <div class="number" id="sudahPulang">-</div>
            </div>
            <div class="stat-card">
                <h3>Belum Pulang</h3>
                <div class="number" id="belumPulang">-</div>
            </div>
        </div>

        <!-- Tidak Hadir Table with Pagination -->
        <div class="table-container" style="margin-bottom: 30px;">
            <h3 style="margin-bottom: 15px; color: #ef4444;">⚠️ Tidak Hadir Hari Ini</h3>

            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px; gap:10px; flex-wrap:wrap;">
                <div style="display:flex; gap:8px; align-items:center;">
                    <label for="tidakHadirPageSize" style="font-size:13px;color:#444;">Tampilkan</label>
                    <select id="tidakHadirPageSize" style="padding:8px;border-radius:6px;border:1px solid #e5e7eb">
                        <option value="20">20</option>
                        <option value="50">50</option>
                        <option value="100">100</option>
                    </select>
                    <span style="font-size:13px;color:#666; margin-left:6px;">baris</span>
                </div>

                <div style="display:flex; gap:8px; align-items:center;">
                    <button id="tidakHadirFirst" style="padding:8px 10px;border-radius:6px;border:1px solid #e5e7eb; background:#f3f4f6;">|&lt;</button>
                    <button id="tidakHadirPrev" style="padding:8px 10px;border-radius:6px;border:1px solid #e5e7eb; background:#f3f4f6;">&lt; Prev</button>
                    <span id="tidakHadirPageInfo" style="font-size:13px;color:#444; padding:0 6px;">Page 1</span>
                    <button id="tidakHadirNext" style="padding:8px 10px;border-radius:6px;border:1px solid #e5e7eb; background:#f3f4f6;">Next &gt;</button>
                    <button id="tidakHadirLast" style="padding:8px 10px;border-radius:6px;border:1px solid #e5e7eb; background:#f3f4f6;">&gt;|</button>
                </div>
            </div>

            <table>
                <thead>
                    <tr>
                        <th>NIK</th>
                        <th>Nama</th>
                        <th>Cabang</th>
                        <th>Shift</th>
                    </tr>
                </thead>
                <tbody id="tidakHadirTable">
                    <tr><td colspan="4" style="text-align: center;">Loading...</td></tr>
                </tbody>
            </table>
        </div>

        <!-- Kehadiran Table with Pagination -->
        <div class="table-container">
            <h3 style="margin-bottom: 15px;">📋 Rekap Kehadiran</h3>

            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px; gap:10px; flex-wrap:wrap;">
                <div style="display:flex; gap:8px; align-items:center;">
                    <label for="kehadiranPageSize" style="font-size:13px;color:#444;">Tampilkan</label>
                    <select id="kehadiranPageSize" style="padding:8px;border-radius:6px;border:1px solid #e5e7eb">
                        <option value="20">20</option>
                        <option value="50">50</option>
                        <option value="100">100</option>
                    </select>
                    <span style="font-size:13px;color:#666; margin-left:6px;">baris</span>
                </div>

                <div style="display:flex; gap:8px; align-items:center;">
                    <button id="kehadiranFirst" style="padding:8px 10px;border-radius:6px;border:1px solid #e5e7eb; background:#f3f4f6;">|&lt;</button>
                    <button id="kehadiranPrev" style="padding:8px 10px;border-radius:6px;border:1px solid #e5e7eb; background:#f3f4f6;">&lt; Prev</button>
                    <span id="kehadiranPageInfo" style="font-size:13px;color:#444; padding:0 6px;">Page 1</span>
                    <button id="kehadiranNext" style="padding:8px 10px;border-radius:6px;border:1px solid #e5e7eb; background:#f3f4f6;">Next &gt;</button>
                    <button id="kehadiranLast" style="padding:8px 10px;border-radius:6px;border:1px solid #e5e7eb; background:#f3f4f6;">&gt;|</button>
                </div>
            </div>

            <table>
                <thead>
                    <tr>
                        <th>Tanggal</th>
                        <th>NIK</th>
                        <th>Nama</th>
                        <th>Cabang</th>
                        <th>Absen Masuk</th>
                        <th>Absen Keluar</th>
                        <th>Durasi</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody id="kehadiranTable">
                    <tr><td colspan="8" style="text-align: center;">Loading...</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <script>
        const themeToggleBtn = document.getElementById('themeToggle');
        initTheme();
        let adminToken = localStorage.getItem('adminToken');
        let currentCabang = '';
        let currentTanggal = '';
        // Pagination state for 'Tidak Hadir Hari Ini'
        let tidakHadirData = [];
        let tidakHadirPage = 1;
        let tidakHadirPageSize = 20; // default 20
        // Pagination state for 'Rekap Kehadiran'
        let kehadiranData = [];
        let kehadiranPage = 1;
        let kehadiranPageSize = 20; // default 20

        // Initialize
        // Function to load total karyawan
        async function loadTotalKaryawan() {
            try {
                const res = await fetch('/api/karyawan');
                if (res.ok) {
                    const data = await res.json();
                    if (data && data.karyawan) {
                        document.getElementById('totalKaryawan').textContent = data.karyawan.length;
                        return data.karyawan.length;
                    }
                }
                return 0;
            } catch (e) {
                console.error('Failed to load total karyawan:', e);
                return 0;
            }
        }

        document.addEventListener('DOMContentLoaded', function() {
            loadCabangListCached();
            setDefaultDate();
            initAutoRefresh();
            
            // Load total karyawan first, then load the dashboard
            loadTotalKaryawan().then(() => {
                loadDashboard();
            }).catch(e => {
                console.error('Error initializing dashboard:', e);
                loadDashboard();
            });
            
            if (adminToken) {
                showAdminPanel();
            }
        });

        function setDefaultDate() {
            const today = new Date();
            today.setHours(today.getHours() + 7); // UTC+7
            document.getElementById('filterTanggal').value = today.toISOString().split('T')[0];
        }

        let autoRefreshInterval = null;
        let lastAutoRefreshTime = 0;
        const AUTO_REFRESH_INTERVAL = 60000;

        function initAutoRefresh() {
            document.addEventListener('visibilitychange', function() {
                if (document.hidden) {
                    if (autoRefreshInterval) {
                        clearInterval(autoRefreshInterval);
                        autoRefreshInterval = null;
                    }
                } else {
                    const timeSinceLastRefresh = Date.now() - lastAutoRefreshTime;
                    if (timeSinceLastRefresh > AUTO_REFRESH_INTERVAL) {
                        loadDashboard();
                    }
                    setupAutoRefresh();
                }
            });
            setupAutoRefresh();
        }

        function setupAutoRefresh() {
            if (!document.hidden && !autoRefreshInterval) {
                lastAutoRefreshTime = Date.now();
                autoRefreshInterval = setInterval(function() {
                    if (!document.hidden) {
                        lastAutoRefreshTime = Date.now();
                        loadDashboard();
                    }
                }, AUTO_REFRESH_INTERVAL);
            }
        }

        let debounceFilterTimer = null;
        function debounceLoadDashboard() {
            if (debounceFilterTimer) clearTimeout(debounceFilterTimer);
            debounceFilterTimer = setTimeout(function() {
                loadDashboard();
            }, 500);
        }

        async function loadCabangListCached() {
            const CACHE_KEY = 'cabang_list_cache';
            const CACHE_TTL = 3600000;
            
            try {
                const cached = localStorage.getItem(CACHE_KEY);
                if (cached) {
                    const { data, timestamp } = JSON.parse(cached);
                    if (Date.now() - timestamp < CACHE_TTL) {
                        renderCabangOptions(data);
                        return;
                    }
                }
                
                const res = await fetch('/api/karyawan');
                const data = await res.json();
                const cabangs = Array.from(new Set(data.karyawan.map(k => k.cabang)));
                
                localStorage.setItem(CACHE_KEY, JSON.stringify({
                    data: cabangs,
                    timestamp: Date.now()
                }));
                
                renderCabangOptions(cabangs);
            } catch (e) {
                console.error('Failed to load cabang list:', e);
            }
        }

        function renderCabangOptions(cabangs) {
            const select = document.getElementById('filterCabang');
            const currentValue = select.value;
            select.innerHTML = '<option value="">Semua Cabang</option>';
            
            cabangs.forEach(cabang => {
                const option = document.createElement('option');
                option.value = cabang;
                option.textContent = cabang;
                select.appendChild(option);
            });
            
            select.value = currentValue;
        }

        async function loadCabangList() {
            return loadCabangListCached();
        }

        function initTheme() {
            const savedTheme = localStorage.getItem('theme') || 'light';
            document.documentElement.setAttribute('data-theme', savedTheme);
            updateThemeIcon(savedTheme);
        }

        function toggleTheme() {
            const current = document.documentElement.getAttribute('data-theme') || 'light';
            const next = current === 'dark' ? 'light' : 'dark';
            document.documentElement.setAttribute('data-theme', next);
            localStorage.setItem('theme', next);
            updateThemeIcon(next);
        }

        function updateThemeIcon(theme) {
            if (themeToggleBtn) {
                themeToggleBtn.textContent = theme === 'dark' ? '☀️' : '🌙';
                themeToggleBtn.title = theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode';
            }
        }

        async function loadDashboard() {
            try {
                currentCabang = document.getElementById('filterCabang').value;
                currentTanggal = document.getElementById('filterTanggal').value;

                // Show loading state
                document.querySelectorAll('.stat-card .number, .percentage').forEach(el => {
                    el.textContent = '...';
                });
                document.getElementById('tidakHadirTable').innerHTML = '<tr><td colspan="4" style="text-align: center;">Memuat data...</td></tr>';
                document.getElementById('kehadiranTable').innerHTML = '<tr><td colspan="8" style="text-align: center;">Memuat data...</td></tr>';

                // Clear any existing error messages
                const existingError = document.querySelector('.error-message');
                if (existingError) existingError.remove();

                // Load data in parallel
                await Promise.allSettled([
                    loadStats(),
                    loadTidakHadir(),
                    loadKehadiran()
                ]);

            } catch (error) {
                console.error('Error in loadDashboard:', error);
                // Show error to user
                const errorDiv = document.createElement('div');
                errorDiv.className = 'error-message';
                errorDiv.style.color = 'red';
                errorDiv.style.padding = '10px';
                errorDiv.style.margin = '10px 0';
                errorDiv.style.border = '1px solid #ff6b6b';
                errorDiv.style.borderRadius = '4px';
                errorDiv.style.backgroundColor = '#fff5f5';
                errorDiv.textContent = 'Gagal memuat data. Silakan coba lagi. Kode Error: ' + (error.status || 'UNKNOWN');
                
                // Insert error message after the header
                const header = document.querySelector('.header');
                if (header) {
                    header.after(errorDiv);
                }
            }
        }

        async function loadStats() {
            try {
                const params = new URLSearchParams();
                if (currentCabang) params.append('cabang', currentCabang);
                
                // Load total karyawan first if not loaded
                if (document.getElementById('totalKaryawan').textContent === '-') {
                    await loadTotalKaryawan();
                }
                
                const res = await fetch('/api/report/today?' + params);
                if (!res.ok) {
                    throw new Error('HTTP error! status: ' + res.status);
                }
                const data = await res.json();

                document.getElementById('hadirHariIni').textContent = data.total_hadir || 0;
                document.getElementById('sudahPulang').textContent = data.sudah_pulang || 0;
                document.getElementById('belumPulang').textContent = data.belum_pulang || 0;

                // Calculate percentage based on total karyawan
                const totalKaryawan = parseInt(document.getElementById('totalKaryawan').textContent) || 0;
                const persentase = totalKaryawan > 0 ? Math.round((data.total_hadir / totalKaryawan) * 100) : 0;
                document.getElementById('persentaseHadir').textContent = persentase + '% dari ' + totalKaryawan + ' karyawan';

            } catch (e) {
                console.error('Failed to load stats:', e);
                document.getElementById('hadirHariIni').textContent = '-';
                document.getElementById('sudahPulang').textContent = '-';
                document.getElementById('belumPulang').textContent = '-';
                document.getElementById('persentaseHadir').textContent = 'Error';
                throw e; // Re-throw to be caught by the parent function
            }
        }

        async function loadTidakHadir() {
            try {
                const params = new URLSearchParams();
                if (currentCabang) params.append('cabang', currentCabang);
                if (currentTanggal) params.append('tanggal', currentTanggal);
                params.append('page', tidakHadirPage);
                params.append('pageSize', tidakHadirPageSize);

                const res = await fetch('/api/report/tidak-hadir?' + params);
                if (!res.ok) {
                    throw new Error('HTTP error! status: ' + res.status);
                }
                const data = await res.json();

                tidakHadirData = data.data || [];
                tidakHadirTotalRows = data.total || 0;
                renderTidakHadirPage();

            } catch (e) {
                console.error('Failed to load tidak hadir:', e);
                const tbody = document.getElementById('tidakHadirTable');
                tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: #ef4444;">Gagal memuat data. Silakan refresh halaman.</td></tr>';
                throw e; // Re-throw to be caught by the parent function
            }
        }

        function renderTidakHadirPage() {
            const tbody = document.getElementById('tidakHadirTable');
            const pageInfo = document.getElementById('tidakHadirPageInfo');
            const firstBtn = document.getElementById('tidakHadirFirst');
            const prevBtn = document.getElementById('tidakHadirPrev');
            const nextBtn = document.getElementById('tidakHadirNext');
            const lastBtn = document.getElementById('tidakHadirLast');

            const total = tidakHadirTotalRows;
            if (total === 0) {
                tbody.innerHTML = '<tr><td data-label="NIK" colspan="4" style="text-align: center; color: #10b981;">Semua karyawan hadir!</td></tr>';
                pageInfo.textContent = 'Page 0 of 0';
                firstBtn.disabled = prevBtn.disabled = nextBtn.disabled = lastBtn.disabled = true;
                return;
            }

            const pageSize = parseInt(tidakHadirPageSize, 10) || 20;
            const totalPages = Math.max(1, Math.ceil(total / pageSize));

            tbody.innerHTML = tidakHadirData.map(function(row) {
                return '<tr>' +
                       '<td data-label="NIK">' + (row.nik || '-') + '</td>' +
                       '<td data-label="Nama">' + (row.nama || '-') + '</td>' +
                       '<td data-label="Cabang">' + (row.cabang || '-') + '</td>' +
                       '<td data-label="Shift">' + (row.shift || '-') + '</td>' +
                       '</tr>';
            }).join('');

            pageInfo.textContent = 'Page ' + tidakHadirPage + ' of ' + totalPages + ' (' + total + ' rows)';

            // Update button states
            firstBtn.disabled = tidakHadirPage === 1;
            prevBtn.disabled = tidakHadirPage === 1;
            nextBtn.disabled = tidakHadirPage === totalPages;
            lastBtn.disabled = tidakHadirPage === totalPages;
        }

        // Setup pagination controls
        (function setupTidakHadirControls(){
            // guard in case DOM not ready
            try {
                const sel = document.getElementById('tidakHadirPageSize');
                if (sel) {
                    sel.value = String(tidakHadirPageSize);
                    sel.addEventListener('change', function(){
                        tidakHadirPageSize = parseInt(this.value,10) || 20;
                        tidakHadirPage = 1;
                        loadTidakHadir();
                    });
                }

                const firstBtn = document.getElementById('tidakHadirFirst');
                const prevBtn = document.getElementById('tidakHadirPrev');
                const nextBtn = document.getElementById('tidakHadirNext');
                const lastBtn = document.getElementById('tidakHadirLast');

                if (firstBtn) firstBtn.addEventListener('click', function(){ tidakHadirPage = 1; loadTidakHadir(); });
                if (prevBtn) prevBtn.addEventListener('click', function(){ if (tidakHadirPage>1) { tidakHadirPage--; loadTidakHadir(); }});
                if (nextBtn) nextBtn.addEventListener('click', function(){ tidakHadirPage++; loadTidakHadir(); });
                if (lastBtn) lastBtn.addEventListener('click', function(){ const pageSize = parseInt(tidakHadirPageSize,10)||20; const total = tidakHadirTotalRows; tidakHadirPage = Math.max(1, Math.ceil(total / pageSize)); loadTidakHadir(); });
            } catch (e) { /* ignore setup errors */ }
        })();

        async function loadKehadiran() {
            try {
                const params = new URLSearchParams();
                if (currentCabang) params.append('cabang', currentCabang);
                const bulan = currentTanggal ? currentTanggal.substring(0, 7) : new Date().toISOString().substring(0, 7);
                params.append('bulan', bulan);
                params.append('page', kehadiranPage);
                params.append('pageSize', kehadiranPageSize);

                const res = await fetch('/api/report/monthly?' + params);
                const data = await res.json();

                kehadiranData = data.data || [];
                kehadiranTotalRows = data.total || 0;
                renderKehadiranPage();

            } catch (e) {
                console.error('Failed to load kehadiran:', e);
            }
        }

        function renderKehadiranPage() {
            const tbody = document.getElementById('kehadiranTable');
            const pageInfo = document.getElementById('kehadiranPageInfo');
            const firstBtn = document.getElementById('kehadiranFirst');
            const prevBtn = document.getElementById('kehadiranPrev');
            const nextBtn = document.getElementById('kehadiranNext');
            const lastBtn = document.getElementById('kehadiranLast');

            const total = kehadiranTotalRows;
            if (total === 0) {
                tbody.innerHTML = '<tr><td data-label="Tanggal" colspan="8" style="text-align: center;">Tidak ada data</td></tr>';
                pageInfo.textContent = 'Page 0 of 0';
                if (firstBtn) firstBtn.disabled = prevBtn.disabled = nextBtn.disabled = lastBtn.disabled = true;
                return;
            }

            const pageSize = parseInt(kehadiranPageSize, 10) || 20;
            const totalPages = Math.max(1, Math.ceil(total / pageSize));

            tbody.innerHTML = kehadiranData.map(row => {
                const persentase = Math.round((row.total_hadir / 22) * 100);
                const statusClass = persentase >= 90 ? 'success' : persentase >= 75 ? 'warning' : 'danger';
                return '<tr>' +
                       '<td data-label="Tanggal">' + (row.tanggal || '-') + '</td>' +
                       '<td data-label="NIK">' + (row.nik || '-') + '</td>' +
                       '<td data-label="Nama">' + (row.nama || '-') + '</td>' +
                       '<td data-label="Cabang">' + (row.cabang || '-') + '</td>' +
                       '<td data-label="Hadir">' + (row.total_hadir || '0') + ' hari</td>' +
                       '<td data-label="Lengkap">' + (row.lengkap || '0') + ' hari</td>' +
                       '<td data-label="Durasi">' + (row.avg_durasi_menit ? Math.round(row.avg_durasi_menit / 60) + ' jam' : '-') + '</td>' +
                       '<td data-label="Status"><span class="badge badge-' + statusClass + '">' + persentase + '%</span></td>' +
                       '</tr>';
            }).join('');

            pageInfo.textContent = 'Page ' + kehadiranPage + ' of ' + totalPages + ' (' + total + ' rows)';

            if (firstBtn) firstBtn.disabled = kehadiranPage === 1;
            if (prevBtn) prevBtn.disabled = kehadiranPage === 1;
            if (nextBtn) nextBtn.disabled = kehadiranPage === totalPages;
            if (lastBtn) lastBtn.disabled = kehadiranPage === totalPages;
        }

        // Setup controls for kehadiran pagination
        (function setupKehadiranControls(){
            try {
                const sel = document.getElementById('kehadiranPageSize');
                if (sel) {
                    sel.value = String(kehadiranPageSize);
                    sel.addEventListener('change', function(){
                        kehadiranPageSize = parseInt(this.value,10) || 20;
                        kehadiranPage = 1;
                        loadKehadiran();
                    });
                }

                const firstBtn = document.getElementById('kehadiranFirst');
                const prevBtn = document.getElementById('kehadiranPrev');
                const nextBtn = document.getElementById('kehadiranNext');
                const lastBtn = document.getElementById('kehadiranLast');

                if (firstBtn) firstBtn.addEventListener('click', function(){ kehadiranPage = 1; loadKehadiran(); });
                if (prevBtn) prevBtn.addEventListener('click', function(){ if (kehadiranPage>1) { kehadiranPage--; loadKehadiran(); }});
                if (nextBtn) nextBtn.addEventListener('click', function(){ kehadiranPage++; loadKehadiran(); });
                if (lastBtn) lastBtn.addEventListener('click', function(){ const pageSize = parseInt(kehadiranPageSize,10)||20; const total = kehadiranTotalRows; kehadiranPage = Math.max(1, Math.ceil(total / pageSize)); loadKehadiran(); });
            } catch (e) { /* ignore setup errors */ }
        })();

        function resetFilter() {
            document.getElementById('filterCabang').value = '';
            setDefaultDate();
            loadDashboard();
        }

        async function adminLogin() {
            const username = document.getElementById('adminUsername').value;
            const password = document.getElementById('adminPassword').value;

            try {
                const res = await fetch('/admin/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });

                const data = await res.json();
                if (data.success) {
                    adminToken = data.token;
                    localStorage.setItem('adminToken', adminToken);
                    try { showAdminPanel(); } catch(e) { /* ignore if dashboard admin elements removed */ }
                } else {
                    alert('Login gagal: ' + data.error);
                }
            } catch (e) {
                alert('Login error: ' + e.message);
            }
        }

        function showAdminPanel() {
            const loginEl = document.getElementById('adminLogin');
            const panelEl = document.getElementById('adminPanel');
            if (!loginEl || !panelEl) return; // dashboard may not include admin UI
            loginEl.classList.add('hidden');
            panelEl.classList.remove('hidden');
        }

        function adminLogout() {
            adminToken = null;
            localStorage.removeItem('adminToken');
            const loginEl = document.getElementById('adminLogin');
            const panelEl = document.getElementById('adminPanel');
            if (loginEl) loginEl.classList.remove('hidden');
            if (panelEl) panelEl.classList.add('hidden');
            const userEl = document.getElementById('adminUsername');
            const passEl = document.getElementById('adminPassword');
            if (userEl) userEl.value = '';
            if (passEl) passEl.value = '';
        }

        async function exportCSV() {
            if (!adminToken) {
                alert('Please login as admin first');
                return;
            }

            try {
                const res = await fetch('/admin/export/csv', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        cabang: currentCabang,
                        startDate: currentTanggal ? currentTanggal.substring(0, 7) + '-01' : null,
                        endDate: currentTanggal,
                        token: adminToken
                    })
                });

                const blob = await res.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = 'absensi-' + new Date().toISOString().split('T')[0] + '.csv';
                a.click();
            } catch (e) {
                alert('Export failed: ' + e.message);
            }
        }

        async function exportExcel() {
            alert('Excel export akan segera tersedia. Gunakan CSV untuk sementara.');
        }

        // Auto refresh every 60 seconds
        setInterval(() => {
            loadDashboard();
        }, 60000);
    </script>
</body>
</html>`;
}

// ============================================================================
// SECTION 7B: EMPLOYEE DASHBOARD HTML
// ============================================================================

function getEmployeeDashboardHTML() {
    return `<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard Karyawan</title>
    <style>
        :root {
            color-scheme: light;
        }
        [data-theme="dark"] {
            color-scheme: dark;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
            color: #1f2937;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        .header {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        .header h1 { color: #667eea; margin-bottom: 5px; }
        .header p { color: #666; font-size: 14px; }
        .tabs {
            display: flex;
            gap: 10px;
            margin-top: 20px;
            border-bottom: 2px solid #e0e0e0;
        }
        .tab {
            padding: 12px 24px;
            background: none;
            border: none;
            border-bottom: 3px solid transparent;
            cursor: pointer;
            font-size: 15px;
            font-weight: 600;
            color: #666;
            transition: 0.3s;
        }
        .tab.active {
            color: #667eea;
            border-bottom-color: #667eea;
        }
        .tab:hover { color: #667eea; }
        .content {
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            border-radius: 12px;
            color: white;
        }
        .stat-card h3 { font-size: 14px; opacity: 0.9; margin-bottom: 8px; }
        .stat-card .number { font-size: 32px; font-weight: bold; }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e0e0e0;
        }
        th {
            background: #f8f9fa;
            font-weight: 600;
            color: #667eea;
        }
        tr:hover { background: #f8f9fa; }
        .badge {
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
        }
        .badge-success { background: #d1fae5; color: #065f46; }
        .badge-warning { background: #fef3c7; color: #92400e; }
        .badge-danger { background: #fee2e2; color: #991b1b; }
        .photo-link {
            color: #667eea;
            text-decoration: none;
            font-size: 12px;
        }
        .photo-link:hover { text-decoration: underline; }
        .loading { opacity: 0.5; pointer-events: none; }
        .theme-toggle {
            position: fixed;
            top: 20px;
            right: 20px;
            width: 48px;
            height: 48px;
            border-radius: 50%;
            border: none;
            background: white;
            box-shadow: 0 12px 30px rgba(0,0,0,0.15);
            cursor: pointer;
            font-size: 20px;
            z-index: 1000;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }
        .theme-toggle:hover {
            transform: scale(1.05);
            box-shadow: 0 15px 35px rgba(0,0,0,0.2);
        }
        .theme-toggle:active { transform: scale(0.95); }
        .back-btn {
            display: inline-block;
            padding: 10px 20px;
            background: #f3f4f6;
            color: #667eea;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            margin-bottom: 20px;
            transition: 0.3s;
        }
        .back-btn:hover { background: #e5e7eb; }
        [data-theme="dark"] body {
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #e2e8f0;
        }
        [data-theme="dark"] .header,
        [data-theme="dark"] .content {
            background: #1f2937;
            color: #e2e8f0;
            box-shadow: 0 10px 30px rgba(0,0,0,0.5);
        }
        [data-theme="dark"] .header h1 { color: #a5b4fc; }
        [data-theme="dark"] .header p { color: #cbd5f5; }
        [data-theme="dark"] .tab {
            color: #94a3b8;
        }
        [data-theme="dark"] .tab.active,
        [data-theme="dark"] .tab:hover {
            color: #a5b4fc;
            border-bottom-color: #a5b4fc;
        }
        [data-theme="dark"] .tabs {
            border-bottom-color: #334155;
        }
        [data-theme="dark"] th {
            background: #0f172a;
            color: #cbd5f5;
        }
        [data-theme="dark"] tr:hover { background: #0f172a; }
        [data-theme="dark"] .back-btn {
            background: #334155;
            color: #cbd5f5;
        }
        [data-theme="dark"] .back-btn:hover { background: #1f2937; }
        [data-theme="dark"] .badge-success { background: #064e3b; color: #6ee7b7; }
        [data-theme="dark"] .badge-warning { background: #78350f; color: #fcd34d; }
        [data-theme="dark"] .badge-danger { background: #7f1d1d; color: #fecaca; }
    </style>
</head>
<body>
    <button class="theme-toggle" id="themeToggle" onclick="toggleTheme()">🌙</button>
    <div class="container">
        <a href="/absen" class="back-btn">← Kembali ke Absen</a>
        
        <div class="header">
            <h1>📊 Dashboard Saya</h1>
            <p id="employeeName">Loading...</p>
            
            <div class="tabs">
                <button class="tab active" onclick="switchTab('daily')">Hari Ini</button>
                <button class="tab" onclick="switchTab('weekly')">Mingguan</button>
                <button class="tab" onclick="switchTab('monthly')">Bulanan</button>
            </div>
        </div>

        <!-- Daily Tab -->
        <div id="daily" class="tab-content active">
            <div class="content">
                <h2 style="margin-bottom: 20px; color: #667eea;">Kehadiran Hari Ini</h2>
                <div id="dailyContent">
                    <p style="text-align: center; color: #666;">Loading...</p>
                </div>
            </div>
        </div>

        <!-- Weekly Tab -->
        <div id="weekly" class="tab-content">
            <div class="content">
                <h2 style="margin-bottom: 20px; color: #667eea;">Kehadiran 7 Hari Terakhir</h2>
                <div id="weeklyContent">
                    <p style="text-align: center; color: #666;">Loading...</p>
                </div>
            </div>
        </div>

        <!-- Monthly Tab -->
        <div id="monthly" class="tab-content">
            <div class="content">
                <h2 style="margin-bottom: 20px; color: #667eea;">Kehadiran Bulan Ini</h2>
                <div class="stats" id="monthlyStats"></div>
                <div id="monthlyContent">
                    <p style="text-align: center; color: #666;">Loading...</p>
                </div>
            </div>
        </div>
    </div>

    <script>
        let user = null;
        const themeToggleBtn = document.getElementById('themeToggle');
        initTheme();

        document.addEventListener('DOMContentLoaded', function() {
            const userStr = localStorage.getItem('user');
            if (!userStr) {
                window.location.href = '/';
                return;
            }
            user = JSON.parse(userStr);
            
            const displayName = user.isBuffer ? user.namaBuffer : user.nama;
            const nik = user.isBuffer ? user.karyawanNik : user.nik;
            document.getElementById('employeeName').textContent = displayName + ' (' + nik + ')';
            
            loadDaily();
        });

        function initTheme() {
            const savedTheme = localStorage.getItem('theme') || 'light';
            document.documentElement.setAttribute('data-theme', savedTheme);
            updateThemeIcon(savedTheme);
        }

        function toggleTheme() {
            const current = document.documentElement.getAttribute('data-theme') || 'light';
            const next = current === 'dark' ? 'light' : 'dark';
            document.documentElement.setAttribute('data-theme', next);
            localStorage.setItem('theme', next);
            updateThemeIcon(next);
        }

        function updateThemeIcon(theme) {
            if (themeToggleBtn) {
                themeToggleBtn.textContent = theme === 'dark' ? '☀️' : '🌙';
                themeToggleBtn.title = theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode';
            }
        }

        function switchTab(tabName) {
            // Update tab buttons
            document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
            event.target.classList.add('active');
            
            // Update tab content
            document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
            document.getElementById(tabName).classList.add('active');
            
            // Load data
            if (tabName === 'daily') loadDaily();
            else if (tabName === 'weekly') loadWeekly();
            else if (tabName === 'monthly') loadMonthly();
        }

        async function loadDaily() {
            try {
                const nik = user.isBuffer ? user.karyawanNik : user.nik;
                const res = await fetch('/api/report/employee/daily?nik=' + nik);
                const result = await res.json();
                
                const container = document.getElementById('dailyContent');
                if (!result.data) {
                    container.innerHTML = '<p style="text-align: center; color: #ef4444;">Belum ada data kehadiran hari ini.</p>';
                    return;
                }
                
                const data = result.data;
                container.innerHTML = \`
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px;">
                        <div style="background: #f8f9fa; padding: 15px; border-radius: 10px;">
                            <h4 style="color: #10b981; margin-bottom: 10px;">Absen Masuk</h4>
                            <p><strong>Waktu:</strong> \${data.time_in || '-'}</p>
                            <p><strong>Jarak:</strong> \${data.jarak_in || '-'} meter</p>
                            <p><strong>Lokasi:</strong> <a href="https://www.google.com/maps?q=\${data.lokasi_in_lat},\${data.lokasi_in_lng}" target="_blank" class="photo-link">Lihat Map</a></p>
                            \${data.photo_in_url ? '<p><a href="' + data.photo_in_url + '" target="_blank" class="photo-link">📷 Lihat Foto</a></p>' : ''}
                        </div>
                        <div style="background: #f8f9fa; padding: 15px; border-radius: 10px;">
                            <h4 style="color: #ef4444; margin-bottom: 10px;">Absen Pulang</h4>
                            <p><strong>Waktu:</strong> \${data.time_out || 'Belum Absen Pulang'}</p>
                            <p><strong>Jarak:</strong> \${data.jarak_out || '-'} meter</p>
                            \${data.lokasi_out_lat ? '<p><strong>Lokasi:</strong> <a href="https://www.google.com/maps?q=' + data.lokasi_out_lat + ',' + data.lokasi_out_lng + '" target="_blank" class="photo-link">Lihat Map</a></p>' : ''}
                            \${data.photo_out_url ? '<p><a href="' + data.photo_out_url + '" target="_blank" class="photo-link">📷 Lihat Foto</a></p>' : ''}
                        </div>
                    </div>
                    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 20px; border-radius: 10px; color: white; text-align: center;">
                        <h3>Durasi Kerja</h3>
                        <p style="font-size: 24px; font-weight: bold; margin-top: 10px;">\${data.durasi_text || 'Belum selesai'}</p>
                    </div>
                \`;
            } catch (e) {
                console.error('Failed to load daily:', e);
                document.getElementById('dailyContent').innerHTML = '<p style="text-align: center; color: #ef4444;">Error loading data</p>';
            }
        }

        async function loadWeekly() {
            try {
                const nik = user.isBuffer ? user.karyawanNik : user.nik;
                const res = await fetch('/api/report/employee/weekly?nik=' + nik);
                const result = await res.json();
                
                const container = document.getElementById('weeklyContent');
                if (result.data.length === 0) {
                    container.innerHTML = '<p style="text-align: center; color: #666;">Tidak ada data kehadiran minggu ini.</p>';
                    return;
                }
                
                container.innerHTML = \`
                    <table>
                        <thead>
                            <tr>
                                <th>Tanggal</th>
                                <th>Absen Masuk</th>
                                <th>Absen Keluar</th>
                                <th>Durasi</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            \${result.data.map(row => \`
                                <tr>
                                    <td>\${row.tanggal}</td>
                                    <td>\${row.time_in || '-'}</td>
                                    <td>\${row.time_out || '-'}</td>
                                    <td>\${row.durasi_text || '-'}</td>
                                    <td>
                                        <span class="badge \${row.time_out ? 'badge-success' : 'badge-warning'}">
                                            \${row.time_out ? 'Lengkap' : 'Belum Selesai'}
                                        </span>
                                    </td>
                                </tr>
                            \`).join('')}
                        </tbody>
                    </table>
                \`;
            } catch (e) {
                console.error('Failed to load weekly:', e);
                document.getElementById('weeklyContent').innerHTML = '<p style="text-align: center; color: #ef4444;">Error loading data</p>';
            }
        }

        async function loadMonthly() {
            try {
                const nik = user.isBuffer ? user.karyawanNik : user.nik;
                const res = await fetch('/api/report/employee/monthly?nik=' + nik);
                const result = await res.json();
                
                // Update stats
                const statsContainer = document.getElementById('monthlyStats');
                const summary = result.summary;
                statsContainer.innerHTML = \`
                    <div class="stat-card">
                        <h3>Total Hadir</h3>
                        <div class="number">\${summary.total_hadir}</div>
                    </div>
                    <div class="stat-card">
                        <h3>Lengkap</h3>
                        <div class="number">\${summary.lengkap}</div>
                    </div>
                    <div class="stat-card">
                        <h3>Rata-rata Durasi</h3>
                        <div class="number">\${summary.avg_durasi_jam}h</div>
                    </div>
                \`;
                
                // Update table
                const container = document.getElementById('monthlyContent');
                if (result.data.length === 0) {
                    container.innerHTML = '<p style="text-align: center; color: #666;">Tidak ada data kehadiran bulan ini.</p>';
                    return;
                }
                
                container.innerHTML = \`
                    <table>
                        <thead>
                            <tr>
                                <th>Tanggal</th>
                                <th>Absen Masuk</th>
                                <th>Absen Keluar</th>
                                <th>Durasi</th>
                                <th>Jarak In</th>
                                <th>Jarak Out</th>
                                <th>Foto</th>
                            </tr>
                        </thead>
                        <tbody>
                            \${result.data.map(row => \`
                                <tr>
                                    <td>\${row.tanggal}</td>
                                    <td>\${row.time_in || '-'}</td>
                                    <td>\${row.time_out || '-'}</td>
                                    <td>\${row.durasi_text || '-'}</td>
                                    <td>\${row.jarak_in || '-'}m</td>
                                    <td>\${row.jarak_out || '-'}m</td>
                                    <td>
                                        \${row.photo_in_url ? '<a href="' + row.photo_in_url + '" target="_blank" class="photo-link">In</a>' : '-'}
                                        \${row.photo_out_url ? ' | <a href="' + row.photo_out_url + '" target="_blank" class="photo-link">Out</a>' : ''}
                                    </td>
                                </tr>
                            \`).join('')}
                        </tbody>
                    </table>
                \`;
            } catch (e) {
                console.error('Failed to load monthly:', e);
                document.getElementById('monthlyContent').innerHTML = '<p style="text-align: center; color: #ef4444;">Error loading data</p>';
            }
        }
    </script>
</body>
</html>`;
}

// ============================================================================
// Admin Panel Page (simple UI for export)
// ============================================================================
async function handleAdminPanel(request, env) {
    const html = getAdminPanelHTML();
    return new Response(html, {
        headers: { 'Content-Type': 'text/html' }
    });
}

function getAdminPanelHTML() {
    return `<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Export - Presensi</title>
    <style>
        *{box-sizing:border-box;margin:0;padding:0}
        body{font-family:system-ui,Segoe UI,Roboto,Helvetica,Arial;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;color:#1f2937;padding:20px}
        .container{max-width:900px;margin:0 auto;background:white;padding:24px;border-radius:12px;box-shadow:0 10px 30px rgba(0,0,0,0.1)}
        h1{color:#667eea;margin-bottom:6px}
        p{color:#666;margin-bottom:12px}
        .row{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:10px}
        label{font-size:13px;color:#444;margin-bottom:6px;display:block}
        input[type=date], select, input[type=text], input[type=password] {padding:10px;border:1px solid #e5e7eb;border-radius:8px;min-width:0}
        .btn{padding:10px 16px;border-radius:8px;border:none;cursor:pointer;font-weight:700}
        .btn-primary{background:#667eea;color:white}
        .btn-csv{background:#10b981;color:white}
        .btn-logout{background:#ef4444;color:white}
        .muted{color:#6b7280;font-size:13px}
        .hidden{display:none}
        .top-actions{display:flex;gap:10px;margin-bottom:18px}
        a.link{color:#667eea;text-decoration:none;font-weight:600}
    </style>
</head>
<body>
    <div class="container">
        <div class="top-actions">
            <a class="link" href="/dashboard">← Kembali ke Dashboard</a>
            <a class="link" href="/">Kembali ke Login</a>
        </div>
        <h1>🔐 Admin - Export Data</h1>
        <p class="muted">Gunakan halaman ini untuk mengekspor data absensi. Pilih cabang (atau pilih Semua Cabang), tanggal awal dan akhir.</p>

        <div id="loginSection">
            <div style="margin-bottom:10px">
                <label>Username</label>
                <input type="text" id="adminUser" placeholder="Username" />
            </div>
            <div style="margin-bottom:10px">
                <label>Password</label>
                <input type="password" id="adminPass" placeholder="Password" />
            </div>
            <div class="row">
                <button class="btn btn-primary" onclick="adminLogin()">Login</button>
            </div>
        </div>

        <div id="exportSection" class="hidden">
            <p style="color:#10b981;margin-bottom:6px">✅ Anda sudah login sebagai admin</p>
            <div style="margin-bottom:8px">
                <label>Cabang</label>
                <select id="exportCabang">
                    <option value="">-- Semua Cabang --</option>
                </select>
            </div>
            <div style="display:flex;gap:10px;margin-bottom:8px">
                <div style="flex:1">
                    <label>Tanggal Awal</label>
                    <input type="date" id="startDate" />
                </div>
                <div style="flex:1">
                    <label>Tanggal Akhir</label>
                    <input type="date" id="endDate" />
                </div>
            </div>
            <div class="row">
                <button class="btn btn-csv" onclick="exportCSV()">📥 Export CSV</button>
                <button class="btn" onclick="exportExcel()">📊 Export Excel (JSON)</button>
                <button class="btn btn-logout" onclick="adminLogout()">Logout</button>
            </div>
        </div>

        <div id="message" style="margin-top:12px;color:#ef4444"></div>
    </div>

    <script>
        let adminToken = localStorage.getItem('adminToken');

        document.addEventListener('DOMContentLoaded', function(){
            loadCabangOptions();
            const today = new Date();
            const iso = today.toISOString().split('T')[0];
            document.getElementById('endDate').value = iso;
            // default startDate to beginning of month
            const start = iso.substring(0,8) + '01';
            document.getElementById('startDate').value = start;

            if (adminToken) {
                showExportSection();
            }
        });

        async function loadCabangOptions() {
            try {
                const res = await fetch('/api/karyawan');
                const data = await res.json();
                const cabangs = Array.from(new Set((data.karyawan || []).map(k=>k.cabang))).sort();
                const sel = document.getElementById('exportCabang');
                cabangs.forEach(c => {
                    const opt = document.createElement('option'); opt.value = c; opt.textContent = c; sel.appendChild(opt);
                });
            } catch (e) {
                console.error('Failed to load cabang list', e);
            }
        }

        async function adminLogin(){
            const username = document.getElementById('adminUser').value;
            const password = document.getElementById('adminPass').value;
            document.getElementById('message').textContent = '';
            try{
                const res = await fetch('/admin/login', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password})});
                const data = await res.json();
                if (data.success) {
                    adminToken = data.token; localStorage.setItem('adminToken', adminToken); showExportSection();
                } else {
                    document.getElementById('message').textContent = data.error || 'Login gagal';
                }
            } catch(e){ document.getElementById('message').textContent = 'Login error'; }
        }

        function showExportSection(){
            document.getElementById('loginSection').classList.add('hidden');
            document.getElementById('exportSection').classList.remove('hidden');
        }

        function adminLogout(){ adminToken=null; localStorage.removeItem('adminToken'); document.getElementById('exportSection').classList.add('hidden'); document.getElementById('loginSection').classList.remove('hidden'); }

        async function exportCSV(){
            if (!adminToken) { alert('Login terlebih dahulu'); return; }
            const cabang = document.getElementById('exportCabang').value || null;
            const startDate = document.getElementById('startDate').value || null;
            const endDate = document.getElementById('endDate').value || null;
            try{
                const res = await fetch('/admin/export/csv', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({cabang, startDate, endDate, token: adminToken})});
                if (!res.ok) { const err = await res.json().catch(()=>({error:'Unknown'})); document.getElementById('message').textContent = err.error || 'Export failed'; return; }
                const blob = await res.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a'); a.href = url; a.download = 'absensi-' + new Date().toISOString().split('T')[0] + '.csv'; a.click();
            } catch(e){ document.getElementById('message').textContent = 'Export error'; }
        }

        async function exportExcel(){ alert('Excel export akan mengembalikan JSON. Gunakan CSV untuk file siap pakai.');
            if (!adminToken) { alert('Login terlebih dahulu'); return; }
            const cabang = document.getElementById('exportCabang').value || null;
            const startDate = document.getElementById('startDate').value || null;
            const endDate = document.getElementById('endDate').value || null;
            try{
                const res = await fetch('/admin/export/excel', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({cabang, startDate, endDate, token: adminToken})});
                const data = await res.json();
                if (data.error) { document.getElementById('message').textContent = data.error; return; }
                // Offer JSON download
                const blob = new Blob([JSON.stringify(data)], {type: 'application/json'});
                const url = URL.createObjectURL(blob); const a = document.createElement('a'); a.href = url; a.download = data.filename || 'export.json'; a.click();
            } catch(e){ document.getElementById('message').textContent = 'Export error'; }
        }
    </script>
</body>
</html>`;
}

// ============================================================================
// SECTION 8: LOGIN PAGE HTML (Continuing from previous worker.js)
// ============================================================================

function getLoginHTML() {
    return `<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="theme-color" content="#667eea">
    <link rel="manifest" href="/manifest.json">
    <title>Presensi - Login</title>
    <style>
        :root {
            color-scheme: light;
            --bg-gradient-start: #667eea;
            --bg-gradient-end: #764ba2;
            --card-bg: #ffffff;
            --text-primary: #667eea;
            --text-secondary: #666666;
            --body-text: #1f2937;
            --input-bg: #ffffff;
            --input-border: #e0e0e0;
            --input-focus: #667eea;
            --btn-primary: #667eea;
            --btn-primary-hover: #5568d3;
            --btn-secondary: #f3f4f6;
            --btn-secondary-hover: #e5e7eb;
            --btn-secondary-text: #667eea;
            --error-text: #ef4444;
            --card-shadow: rgba(0,0,0,0.3);
        }
        [data-theme="dark"] {
            color-scheme: dark;
            --bg-gradient-start: #0f172a;
            --bg-gradient-end: #1e293b;
            --card-bg: #1f2937;
            --text-primary: #a5b4fc;
            --text-secondary: #cbd5f5;
            --body-text: #e2e8f0;
            --input-bg: #0f172a;
            --input-border: #334155;
            --input-focus: #818cf8;
            --btn-primary: #818cf8;
            --btn-primary-hover: #6366f1;
            --btn-secondary: #334155;
            --btn-secondary-hover: #1f2937;
            --btn-secondary-text: #cbd5f5;
            --error-text: #f87171;
            --card-shadow: rgba(0,0,0,0.6);
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, var(--bg-gradient-start) 0%, var(--bg-gradient-end) 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            color: var(--body-text);
        }
        .container { width: 100%; max-width: 400px; }
        .card {
            background: var(--card-bg);
            padding: 30px;
            border-radius: 20px;
            box-shadow: 0 20px 60px var(--card-shadow);
            position: relative;
            overflow: hidden;
        }
        h1 { color: var(--text-primary); text-align: center; margin-bottom: 5px; font-size: 24px; }
        p { text-align: center; color: var(--text-secondary); margin-bottom: 25px; font-size: 14px; }
        
        .input-group { margin-bottom: 15px; }
        label { display: block; font-size: 12px; color: var(--text-secondary); margin-bottom: 5px; }
        
        input, select {
            width: 100%;
            padding: 12px;
            border: 2px solid var(--input-border);
            border-radius: 10px;
            font-size: 16px;
            transition: 0.3s;
            background: var(--input-bg);
            color: var(--body-text);
        }
        input:focus { outline: none; border-color: var(--input-focus); }
        
        button {
            width: 100%;
            padding: 14px;
            margin-top: 10px;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: 0.3s;
        }
        .btn-primary { background: var(--btn-primary); color: white; }
        .btn-primary:hover { background: var(--btn-primary-hover); }
        .btn-secondary { background: var(--btn-secondary); color: var(--btn-secondary-text); margin-top: 10px; }
        .btn-secondary:hover { background: var(--btn-secondary-hover); }
        
        .hidden { display: none; }
        .error { color: var(--error-text); text-align: center; margin-top: 10px; font-size: 13px; }
        .back-btn { background: none; color: var(--text-secondary); padding: 5px; margin-top: 10px; font-size: 13px; text-decoration: underline; width: auto; display: block; margin-left: auto; margin-right: auto; }

        /* Search Results Style */
        .search-results {
            max-height: 150px;
            overflow-y: auto;
            border: 1px solid var(--input-border);
            border-radius: 8px;
            margin-top: 5px;
            display: none;
            background: var(--card-bg);
        }
        .search-item {
            padding: 10px;
            border-bottom: 1px solid #f0f0f0;
            cursor: pointer;
            font-size: 14px;
            color: var(--body-text);
        }
        .search-item:hover { background: #f9fafb; }
        .search-item:last-child { border-bottom: none; }
        .selected-item {
            background: #d1fae5;
            padding: 10px;
            border-radius: 8px;
            margin-top: 5px;
            font-size: 14px;
            color: #065f46;
            display: flex; /* Changed from default to flex, but controlled by hidden class */
            justify-content: space-between;
            align-items: center;
        }
        /* Ensure hidden class overrides display: flex */
        .hidden { display: none !important; }
        
        .remove-selection { cursor: pointer; color: #ef4444; font-weight: bold; }
        .theme-toggle {
            position: fixed;
            top: 20px;
            right: 20px;
            width: 48px;
            height: 48px;
            border-radius: 50%;
            border: none;
            background: var(--card-bg);
            color: var(--body-text);
            box-shadow: 0 12px 30px var(--card-shadow);
            cursor: pointer;
            font-size: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }
        .theme-toggle:hover {
            transform: scale(1.05);
            box-shadow: 0 15px 35px var(--card-shadow);
        }
        .theme-toggle:active { transform: scale(0.95); }
        [data-theme="dark"] .search-item:hover { background: #1f2937; }
        [data-theme="dark"] .search-item { border-color: #1f2937; }
        [data-theme="dark"] .selected-item {
            background: #064e3b;
            color: #6ee7b7;
        }
        [data-theme="dark"] .search-results {
            border-color: #334155;
        }
    </style>
</head>
<body>
    <div class="container">
        <button class="theme-toggle" id="themeToggle" onclick="toggleTheme()">🌙</button>
        <!-- Login Form -->
        <div id="loginForm" class="card">
            <h1>Presensi</h1>
            <p>Sistem Absensi Karyawan IAP</p>
            
            <div class="input-group">
                <input type="text" id="nik" placeholder="NIK OMS" />
            </div>
            <div class="input-group">
                <input type="password" id="password" placeholder="Password" />
            </div>
            
            <button class="btn-primary" onclick="login()">MASUK</button>
            <button class="btn-secondary" onclick="toggleBuffer(true)">👥 ABSEN BUFFER</button>
            <button class="btn-secondary" onclick="location.href='/dashboard'" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white;">📊 DASHBOARD SEMUA KARYAWAN</button>
            <div id="loginError" class="error"></div>
        </div>

        <!-- Buffer Form -->
        <div id="bufferForm" class="card hidden">
            <h1>Absen Buffer</h1>
            <p>Khusus Karyawan Pengganti</p>
            
            <div class="input-group">
                <input type="text" id="nikKtp" placeholder="NIK KTP (Anda)" />
            </div>
            <div class="input-group">
                <input type="text" id="namaBuffer" placeholder="Nama Lengkap (Anda)" />
            </div>
            
            <div class="input-group">
                <label>Karyawan yang digantikan:</label>
                <input type="text" id="searchKaryawan" placeholder="Ketik nama karyawan..." oninput="filterKaryawan()" />
                <div id="searchResults" class="search-results"></div>
                
                <!-- Default hidden with !important -->
                <div id="selectedKaryawanDisplay" class="selected-item hidden">
                    <span id="selectedName"></span>
                    <span class="remove-selection" onclick="clearSelection()">✕</span>
                </div>
                <input type="hidden" id="selectedKaryawanNik" />
            </div>

            <button class="btn-primary" onclick="loginBuffer()">MASUK BUFFER</button>
            <button class="back-btn" onclick="toggleBuffer(false)">Kembali ke Login Utama</button>
            <div id="bufferError" class="error"></div>
        </div>
    </div>

    <script>
        let allKaryawan = [];
        const themeToggleBtn = document.getElementById('themeToggle');
        initTheme();

        async function loadKaryawanList() {
            try {
                const res = await fetch('/api/karyawan');
                const data = await res.json();
                allKaryawan = data.karyawan || [];
            } catch (e) {
                console.error('Failed to load karyawan:', e);
            }
        }

        function filterKaryawan() {
            const input = document.getElementById('searchKaryawan');
            const resultsDiv = document.getElementById('searchResults');
            const term = input.value.toLowerCase();
            
            if (term.length < 2) {
                resultsDiv.style.display = 'none';
                return;
            }

            const matches = allKaryawan.filter(k => 
                k.nama.toLowerCase().includes(term) || 
                k.nik.includes(term)
            ).slice(0, 10); // Limit 10 results

            resultsDiv.innerHTML = '';
            if (matches.length > 0) {
                matches.forEach(k => {
                    const div = document.createElement('div');
                    div.className = 'search-item';
                    div.textContent = \`\${k.nama} (\${k.cabang})\`;
                    div.onclick = () => selectKaryawan(k);
                    resultsDiv.appendChild(div);
                });
                resultsDiv.style.display = 'block';
            } else {
                resultsDiv.style.display = 'none';
            }
        }

        function selectKaryawan(k) {
            document.getElementById('selectedKaryawanNik').value = k.nik;
            document.getElementById('selectedName').textContent = \`\${k.nama} (\${k.cabang})\`;
            
            document.getElementById('searchKaryawan').classList.add('hidden');
            document.getElementById('searchResults').style.display = 'none';
            document.getElementById('selectedKaryawanDisplay').classList.remove('hidden');
        }

        function clearSelection() {
            document.getElementById('selectedKaryawanNik').value = '';
            document.getElementById('searchKaryawan').value = '';
            document.getElementById('searchKaryawan').classList.remove('hidden');
            document.getElementById('selectedKaryawanDisplay').classList.add('hidden');
        }

        function toggleBuffer(show) {
            const loginForm = document.getElementById('loginForm');
            const bufferForm = document.getElementById('bufferForm');
            
            if (show) {
                loginForm.classList.add('hidden');
                bufferForm.classList.remove('hidden');
                if (allKaryawan.length === 0) loadKaryawanList();
            } else {
                loginForm.classList.remove('hidden');
                bufferForm.classList.add('hidden');
            }
        }

        let loginAttempts = 0;
        const MAX_LOGIN_ATTEMPTS = 5;
        let loginLockoutTime = 0;
        const LOCKOUT_DURATION = 300000;

        async function login() {
            const nik = document.getElementById('nik').value.trim();
            const password = document.getElementById('password').value;
            const err = document.getElementById('loginError');

            if (!nik || !password) {
                err.textContent = 'NIK dan Password harus diisi';
                return;
            }

            if (loginAttempts >= MAX_LOGIN_ATTEMPTS) {
                const remainingTime = Math.ceil((loginLockoutTime - Date.now()) / 1000);
                if (remainingTime > 0) {
                    err.textContent = 'Terlalu banyak percobaan. Coba lagi dalam ' + remainingTime + ' detik.';
                    return;
                } else {
                    loginAttempts = 0;
                    loginLockoutTime = 0;
                }
            }

            err.innerHTML = '<span class="spinner" style="display:inline-block; width:16px; height:16px; margin-right:8px;"></span>Loading...';

            try {
                const res = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ nik, password })
                });

                const data = await res.json();
                if (data.error) throw new Error(data.error);

                loginAttempts = 0;
                localStorage.setItem('user', JSON.stringify(data.user));
                window.location.href = '/absen'; 
            } catch (e) {
                loginAttempts++;
                if (loginAttempts >= MAX_LOGIN_ATTEMPTS) {
                    loginLockoutTime = Date.now() + LOCKOUT_DURATION;
                    err.textContent = 'Terlalu banyak percobaan. Akun dikunci selama 5 menit.';
                } else {
                    const remaining = MAX_LOGIN_ATTEMPTS - loginAttempts;
                    err.textContent = e.message + ' (' + remaining + ' percobaan tersisa)';
                }
            }
        }

        async function loginBuffer() {
            const nikKtp = document.getElementById('nikKtp').value.trim();
            const namaBuffer = document.getElementById('namaBuffer').value.trim();
            const karyawanNik = document.getElementById('selectedKaryawanNik').value;
            const err = document.getElementById('bufferError');

            if (!nikKtp || !namaBuffer || !karyawanNik) {
                err.textContent = 'Semua field harus diisi';
                return;
            }

            err.textContent = 'Loading...';

            try {
                const res = await fetch('/api/login-buffer', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ nikKtp, namaBuffer, karyawanNik })
                });

                const data = await res.json();
                if (data.error) throw new Error(data.error);

                localStorage.setItem('user', JSON.stringify(data.buffer));
                window.location.href = '/absen';
            } catch (e) {
                err.textContent = e.message;
            }
        }

        // Enter key support
        document.getElementById('password').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') login();
        });

        function initTheme() {
            const savedTheme = localStorage.getItem('theme') || 'light';
            document.documentElement.setAttribute('data-theme', savedTheme);
            updateThemeIcon(savedTheme);
        }

        function toggleTheme() {
            const current = document.documentElement.getAttribute('data-theme') || 'light';
            const next = current === 'dark' ? 'light' : 'dark';
            document.documentElement.setAttribute('data-theme', next);
            localStorage.setItem('theme', next);
            updateThemeIcon(next);
        }

        function updateThemeIcon(theme) {
            if (themeToggleBtn) {
                themeToggleBtn.textContent = theme === 'dark' ? '☀️' : '🌙';
                themeToggleBtn.title = theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode';
            }
        }

        // Register Service Worker for PWA
        if ('serviceWorker' in navigator) {
            navigator.serviceWorker.register('/sw.js')
                .then(function(registration) {
                    console.log('Service Worker registered:', registration);
                })
                .catch(function(error) {
                    console.log('Service Worker registration failed:', error);
                });
        }
    </script>
</body>
</html>`;
}

// ============================================================================
// SECTION 10: ABSEN PAGE HTML (NEW)
// ============================================================================

function getAbsenHTML() {
    return `<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Absen Karyawan</title>
    <style>
        :root {
            color-scheme: light;
            --body-bg: #f3f4f6;
            --card-bg: #ffffff;
            --text-primary: #1f2937;
            --text-secondary: #6b7280;
            --accent: #2563eb;
            --clock-color: #2563eb;
            --button-in: #10b981;
            --button-out: #ef4444;
            --button-disabled: #e5e7eb;
            --button-disabled-text: #9ca3af;
            --location-bg: #f3f4f6;
            --badge-in-bg: #d1fae5;
            --badge-in-text: #065f46;
            --badge-out-bg: #fee2e2;
            --badge-out-text: #991b1b;
            --logout-bg: #fee2e2;
            --logout-text: #ef4444;
            --settings-bg: #fef3c7;
            --settings-text: #92400e;
            --card-shadow: rgba(0,0,0,0.1);
        }
        [data-theme="dark"] {
            color-scheme: dark;
            --body-bg: #0f172a;
            --card-bg: #1f2937;
            --text-primary: #e2e8f0;
            --text-secondary: #cbd5f5;
            --accent: #93c5fd;
            --clock-color: #93c5fd;
            --button-in: #059669;
            --button-out: #b91c1c;
            --button-disabled: #334155;
            --button-disabled-text: #64748b;
            --location-bg: #1e293b;
            --badge-in-bg: #064e3b;
            --badge-in-text: #6ee7b7;
            --badge-out-bg: #7f1d1d;
            --badge-out-text: #fecaca;
            --logout-bg: #7f1d1d;
            --logout-text: #fecaca;
            --settings-bg: #78350f;
            --settings-text: #fcd34d;
            --card-shadow: rgba(0,0,0,0.45);
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--body-bg);
            min-height: 100vh;
            padding: 15px;
            color: var(--text-primary);
        }
        .container { max-width: 500px; margin: 0 auto; }
        .card {
            background: var(--card-bg);
            padding: 20px;
            border-radius: 20px;
            box-shadow: 0 4px 6px var(--card-shadow);
            margin-bottom: 20px;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        .user-info h2 { font-size: 18px; color: var(--text-primary); font-weight: 700; }
        .user-info p { font-size: 14px; color: var(--text-secondary); }
        
        .info-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
            margin-bottom: 15px;
            background: var(--location-bg);
            padding: 15px;
            border-radius: 12px;
        }
        .info-item { font-size: 13px; color: var(--text-secondary); }
        .info-label { color: var(--text-secondary); margin-bottom: 2px; }
        .info-value { color: var(--text-primary); font-weight: 600; }

        .clock {
            font-size: 42px;
            font-weight: bold;
            text-align: center;
            color: var(--clock-color);
            margin: 15px 0;
            font-family: monospace;
            letter-spacing: -1px;
        }
        .date { text-align: center; color: var(--text-secondary); margin-bottom: 20px; font-size: 14px; }
        
        .camera-container {
            width: 100%;
            height: 350px; /* Taller for better selfie view */
            background: #000;
            border-radius: 15px;
            overflow: hidden;
            position: relative;
            margin-bottom: 20px;
        }
        video, canvas, img {
            width: 100%;
            height: 100%;
            object-fit: cover;
        }
        
        .btn-group {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
        }
        button {
            padding: 16px;
            border: none;
            border-radius: 12px;
            font-size: 16px;
            font-weight: 700;
            cursor: pointer;
            transition: 0.2s;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
        }
        .btn-in { background: var(--button-in); color: white; box-shadow: 0 4px 6px rgba(16, 185, 129, 0.3); }
        .btn-in:active { transform: scale(0.98); }
        .btn-out { background: var(--button-out); color: white; box-shadow: 0 4px 6px rgba(239, 68, 68, 0.3); }
        .btn-out:active { transform: scale(0.98); }
        .btn-disabled { background: var(--button-disabled); color: var(--button-disabled-text); cursor: not-allowed; box-shadow: none; }
        
        .status-badge {
            display: inline-block;
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: 600;
            margin-top: 5px;
        }
        .status-in { background: var(--badge-in-bg); color: var(--badge-in-text); }
        .status-out { background: var(--badge-out-bg); color: var(--badge-out-text); }
        
        .location-info {
            font-size: 12px;
            color: var(--text-secondary);
            text-align: center;
            margin-top: 10px;
            background: var(--location-bg);
            padding: 8px;
            border-radius: 8px;
        }
        .logout-btn {
            background: var(--logout-bg);
            color: var(--logout-text);
            font-size: 12px;
            padding: 8px 12px;
            border-radius: 8px;
            font-weight: 600;
        }
        .settings-btn {
            background: var(--settings-bg);
            color: var(--settings-text);
            font-size: 16px;
            padding: 8px 12px;
            border-radius: 8px;
            font-weight: 600;
            cursor: pointer;
            border: none;
            transition: 0.3s;
        }
        .settings-btn:hover {
            opacity: 0.9;
        }
        .theme-toggle {
            position: fixed;
            top: 15px;
            right: 15px;
            width: 48px;
            height: 48px;
            border-radius: 50%;
            border: none;
            background: var(--card-bg);
            color: var(--text-primary);
            box-shadow: 0 12px 30px var(--card-shadow);
            cursor: pointer;
            font-size: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
            z-index: 1000;
        }
        .theme-toggle:hover {
            transform: scale(1.05);
            box-shadow: 0 15px 35px var(--card-shadow);
        }
        .theme-toggle:active { transform: scale(0.95); }
    </style>
</head>
<body>
    <div class="container">
        <button class="theme-toggle" id="themeToggle" onclick="toggleTheme()">🌙</button>
        <div class="header">
            <div class="user-info">
                <h2 id="userName">Loading...</h2>
                <p id="userRole">-</p>
            </div>
            <div style="display: flex; gap: 8px;">
                <button class="settings-btn" onclick="location.href='/change-password'" title="Ganti Password">
                    🔐
                </button>
                <button class="logout-btn" onclick="logout()">Logout</button>
            </div>
        </div>

        <div class="card">
            <!-- Info Grid -->
            <div class="info-grid">
                <div class="info-item">
                    <div class="info-label">NIK OMS</div>
                    <div class="info-value" id="infoNik">-</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Shift</div>
                    <div class="info-value" id="infoShift">-</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Cabang</div>
                    <div class="info-value" id="infoCabang">-</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Stock Point</div>
                    <div class="info-value" id="infoSP">-</div>
                </div>
            </div>

            <div class="clock" id="clock">00:00:00</div>
            <div class="date" id="date">-</div>
            
            <div class="camera-container">
                <video id="video" autoplay playsinline></video>
                <canvas id="canvas" style="display:none;"></canvas>
                <img id="photoPreview" style="display:none;" />
            </div>

            <div class="btn-group">
                <button id="btnIn" class="btn-in" onclick="clockIn()">ABSEN MASUK</button>
                <button id="btnOut" class="btn-out" onclick="clockOut()">ABSEN KELUAR</button>
            </div>
            
            <div class="location-info" id="locationInfo">📍 Mencari lokasi...</div>
        </div>

        <div class="card">
            <h3 style="font-size: 16px; margin-bottom: 10px;">Riwayat Hari Ini</h3>
            <div id="todayStatus" style="font-size: 14px; color: var(--text-secondary);">
                Belum ada data.
            </div>
        </div>
        
        <div style="text-align: center; margin-top: 20px; padding-bottom: 20px;">
            <a href="/dashboard/employee" style="display: inline-block; padding: 14px 30px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; text-decoration: none; font-size: 15px; font-weight: 600; border-radius: 12px; box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4); transition: 0.3s;">
                📊 Dashboard Saya
            </a>
        </div>
    </div>

    <script>
        let user = null;
        let stream = null;
        let currentLat = 0;
        let currentLng = 0;
        const themeToggleBtn = document.getElementById('themeToggle');
        initTheme();

        // Init
        document.addEventListener('DOMContentLoaded', async () => {
            const userStr = localStorage.getItem('user');
            if (!userStr) {
                window.location.href = '/';
                return;
            }
            user = JSON.parse(userStr);
            
            // Populate Info
            if (user.isBuffer) {
                document.getElementById('userName').textContent = user.namaBuffer + ' (Buffer)';
                document.getElementById('userRole').textContent = 'Menggantikan: ' + user.karyawanNama;
                document.getElementById('infoNik').textContent = user.nikKtp;
            } else {
                document.getElementById('userName').textContent = user.nama;
                document.getElementById('userRole').textContent = user.jabatan || 'Karyawan';
                document.getElementById('infoNik').textContent = user.nik;
            }
            
            document.getElementById('infoShift').textContent = user.shift || '-';
            document.getElementById('infoCabang').textContent = user.cabang || '-';
            document.getElementById('infoSP').textContent = user.stockPoint || '-';
            
            updateClock();
            setInterval(updateClock, 1000);
            
            await initCamera();
            initLocation();
            checkStatus();
        });

        function updateClock() {
            const now = new Date();
            document.getElementById('clock').textContent = now.toLocaleTimeString('id-ID', { hour12: false });
            document.getElementById('date').textContent = now.toLocaleDateString('id-ID', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });
        }

        async function initCamera() {
            try {
                const video = document.getElementById('video');
                const photoPreview = document.getElementById('photoPreview');
                
                // Reset UI
                video.style.display = 'block';
                photoPreview.style.display = 'none';
                
                stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'user' } });
                video.srcObject = stream;
            } catch (e) {
                alert('Gagal akses kamera: ' + e.message);
            }
        }

        function freezeCamera(photoDataUrl) {
            const video = document.getElementById('video');
            const photoPreview = document.getElementById('photoPreview');
            
            // Stop stream
            if (stream) {
                stream.getTracks().forEach(track => track.stop());
            }
            
            // Show photo
            video.style.display = 'none';
            photoPreview.src = photoDataUrl;
            photoPreview.style.display = 'block';
        }

        function initLocation() {
            if (!navigator.geolocation) {
                document.getElementById('locationInfo').textContent = 'Geolocation tidak didukung browser ini.';
                return;
            }
            navigator.geolocation.watchPosition(
                (pos) => {
                    currentLat = pos.coords.latitude;
                    currentLng = pos.coords.longitude;
                    document.getElementById('locationInfo').textContent = \`📍 \${currentLat.toFixed(5)}, \${currentLng.toFixed(5)}\`;
                },
                (err) => {
                    document.getElementById('locationInfo').textContent = '⚠️ Gagal ambil lokasi: ' + err.message;
                },
                { enableHighAccuracy: true }
            );
        }

        async function checkStatus() {
            try {
                const params = new URLSearchParams();
                if (user.isBuffer) {
                    params.append('isBuffer', 'true');
                    params.append('nikKtp', user.nikKtp);
                } else {
                    params.append('nik', user.nik);
                }

                const res = await fetch('/api/status?' + params);
                const data = await res.json();

                const btnIn = document.getElementById('btnIn');
                const btnOut = document.getElementById('btnOut');
                const statusDiv = document.getElementById('todayStatus');

                if (data.clockIn) {
                    btnIn.disabled = true;
                    btnIn.classList.add('btn-disabled');
                    btnIn.innerHTML = '✅ SUDAH MASUK';
                    
                    if (data.clockOut) {
                        btnOut.disabled = true;
                        btnOut.classList.add('btn-disabled');
                        btnOut.innerHTML = '✅ SUDAH PULANG';
                        statusDiv.innerHTML = \`
                            <div class="status-badge status-in">Masuk: \${data.clockIn.split(' ')[1]}</div>
                            <div class="status-badge status-out">Pulang: \${data.clockOut.split(' ')[1]}</div>
                            <div style="margin-top:8px; font-weight:bold;">⏱️ Durasi: \${data.durasi}</div>
                        \`;
                    } else {
                        btnOut.disabled = false;
                        btnOut.classList.remove('btn-disabled');
                        statusDiv.innerHTML = \`<div class="status-badge status-in">Masuk: \${data.clockIn.split(' ')[1]}</div>\`;
                    }
                } else {
                    btnIn.disabled = false;
                    btnOut.disabled = true;
                    btnOut.classList.add('btn-disabled');
                    statusDiv.textContent = 'Belum absen hari ini.';
                }

            } catch (e) {
                console.error('Check status error:', e);
            }
        }

        function takePhoto() {
            const video = document.getElementById('video');
            const canvas = document.getElementById('canvas');
            canvas.width = video.videoWidth;
            canvas.height = video.videoHeight;
            canvas.getContext('2d').drawImage(video, 0, 0);
            return canvas.toDataURL('image/jpeg', 0.7);
        }

        async function clockIn() {
            if (!confirm('Apakah anda yakin ingin Absen Masuk?')) return;
            
            const btn = document.getElementById('btnIn');
            const originalText = btn.innerHTML;
            btn.innerHTML = '<span class="spinner" style="display:inline-block; width:16px; height:16px; margin-right:6px;"></span>Loading...';
            btn.disabled = true;

            try {
                const photo = takePhoto();
                const res = await fetch('/api/clockin', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({...user, lat: currentLat, lng: currentLng, photoBase64: photo, jarak: 0})
                });
                const data = await res.json();
                if (data.error) throw new Error(data.error);
                freezeCamera(photo);
                await checkStatus();
                alert('Absen Masuk Berhasil!');
            } catch (e) {
                alert('Gagal: ' + e.message);
                btn.disabled = false;
                btn.innerHTML = originalText;
            }
        }

        async function clockOut() {
            if (!confirm('Apakah anda yakin ingin Absen Pulang?')) return;
            
            const btn = document.getElementById('btnOut');
            const originalText = btn.innerHTML;
            btn.innerHTML = '<span class="spinner" style="display:inline-block; width:16px; height:16px; margin-right:6px;"></span>Loading...';
            btn.disabled = true;

            try {
                const photo = takePhoto();
                const res = await fetch('/api/clockout', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({...user, lat: currentLat, lng: currentLng, photoBase64: photo, jarak: 0})
                });
                const data = await res.json();
                if (data.error) throw new Error(data.error);
                freezeCamera(photo);
                await checkStatus();
                alert('Absen Pulang Berhasil!');
            } catch (e) {
                alert('Gagal: ' + e.message);
                btn.disabled = false;
                btn.innerHTML = originalText;
            }
        }        function logout() {
            localStorage.removeItem('user');
            window.location.href = '/';
        }

        function initTheme() {
            const savedTheme = localStorage.getItem('theme') || 'light';
            document.documentElement.setAttribute('data-theme', savedTheme);
            updateThemeIcon(savedTheme);
        }

        function toggleTheme() {
            const current = document.documentElement.getAttribute('data-theme') || 'light';
            const next = current === 'dark' ? 'light' : 'dark';
            document.documentElement.setAttribute('data-theme', next);
            localStorage.setItem('theme', next);
            updateThemeIcon(next);
        }

        function updateThemeIcon(theme) {
            if (themeToggleBtn) {
                themeToggleBtn.textContent = theme === 'dark' ? '☀️' : '🌙';
                themeToggleBtn.title = theme === 'dark' ? 'Switch to Light Mode' : 'Switch to Dark Mode';
            }
        }

        // Register Service Worker for PWA
        if ('serviceWorker' in navigator) {
            navigator.serviceWorker.register('/sw.js')
                .then(function(registration) {
                    console.log('Service Worker registered:', registration);
                })
                .catch(function(error) {
                    console.log('Service Worker registration failed:', error);
                });
        }
    </script>
</body>
</html>`;
}

// ============================================================================
// SECTION 9: HTML untuk halaman ganti password
// ============================================================================

function getChangePasswordHTML() {
    return `<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ganti Password</title>
    <style>
        :root {
            --bg-gradient-start: #667eea;
            --bg-gradient-end: #764ba2;
            --card-bg: #ffffff;
            --text-primary: #1f2937;
            --text-secondary: #6b7280;
            --input-bg: #ffffff;
            --input-border: #e0e0e0;
            --input-focus: #667eea;
            --btn-primary: #667eea;
            --btn-primary-hover: #5568d3;
            --btn-secondary: #f3f4f6;
            --btn-secondary-text: #667eea;
            --error-bg: #fee2e2;
            --error-text: #991b1b;
            --success-bg: #d1fae5;
            --success-text: #065f46;
            --badge-bg: #f9fafb;
            --req-met: #10b981;
            --req-unmet: #ef4444;
            --strength-weak: #ef4444;
            --strength-medium: #f59e0b;
            --strength-strong: #10b981;
        }

        [data-theme="dark"] {
            --bg-gradient-start: #1e293b;
            --bg-gradient-end: #0f172a;
            --card-bg: #1e293b;
            --text-primary: #f1f5f9;
            --text-secondary: #cbd5e1;
            --input-bg: #334155;
            --input-border: #475569;
            --input-focus: #667eea;
            --btn-primary: #667eea;
            --btn-primary-hover: #5568d3;
            --btn-secondary: #334155;
            --btn-secondary-text: #94a3b8;
            --error-bg: #7f1d1d;
            --error-text: #fca5a5;
            --success-bg: #064e3b;
            --success-text: #6ee7b7;
            --badge-bg: #334155;
            --req-met: #6ee7b7;
            --req-unmet: #fca5a5;
            --strength-weak: #ef4444;
            --strength-medium: #f59e0b;
            --strength-strong: #10b981;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, var(--bg-gradient-start) 0%, var(--bg-gradient-end) 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            transition: background 0.3s ease;
        }
        .theme-toggle {
            position: fixed;
            top: 20px;
            right: 20px;
            background: var(--card-bg);
            border: none;
            width: 50px;
            height: 50px;
            border-radius: 50%;
            cursor: pointer;
            box-shadow: 0 4px 12px rgba(0,0,0,0.2);
            font-size: 24px;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.3s ease;
            z-index: 1000;
        }
        .theme-toggle:hover {
            transform: scale(1.1) rotate(15deg);
            box-shadow: 0 6px 20px rgba(0,0,0,0.3);
        }
        .theme-toggle:active {
            transform: scale(0.95);
        }
        .container { width: 100%; max-width: 450px; }
        .card {
            background: var(--card-bg);
            padding: 30px;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            transition: background 0.3s ease;
        }
        .header {
            text-align: center;
            margin-bottom: 25px;
        }
        .header h1 { 
            color: var(--btn-primary); 
            font-size: 24px; 
            margin-bottom: 5px; 
        }
        .header p { 
            color: var(--text-secondary); 
            font-size: 14px; 
        }
        .user-badge {
            background: var(--badge-bg);
            padding: 12px;
            border-radius: 10px;
            margin-bottom: 20px;
            text-align: center;
        }
        .user-badge strong { 
            color: var(--btn-primary); 
            font-size: 16px; 
        }
        .user-badge small { 
            display: block; 
            color: var(--text-secondary); 
            margin-top: 3px; 
            font-size: 13px; 
        }
        .input-group { 
            margin-bottom: 15px; 
        }
        label { 
            display: block; 
            font-size: 13px; 
            color: var(--text-secondary); 
            margin-bottom: 6px; 
            font-weight: 600;
        }
        input {
            width: 100%;
            padding: 12px;
            border: 2px solid var(--input-border);
            border-radius: 10px;
            font-size: 15px;
            transition: 0.3s;
            background: var(--input-bg);
            color: var(--text-primary);
        }
        input:focus { 
            outline: none; 
            border-color: var(--input-focus); 
        }
        input.error { 
            border-color: var(--req-unmet); 
        }
        .password-input-wrapper {
            position: relative;
            display: flex;
            align-items: center;
        }
        .password-input-wrapper input {
            padding-right: 45px;
        }
        .toggle-password {
            position: absolute;
            right: 8px;
            background: none;
            border: none;
            cursor: pointer;
            padding: 8px;
            font-size: 18px;
            opacity: 0.6;
            transition: 0.2s;
            width: auto;
            margin: 0;
        }
        .toggle-password:hover {
            opacity: 1;
            transform: scale(1.1);
        }
        .toggle-password:active {
            transform: scale(0.95);
        }
        .password-hint {
            font-size: 12px;
            color: var(--text-secondary);
            margin-top: 4px;
        }
        button {
            width: 100%;
            padding: 14px;
            margin-top: 10px;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: 0.3s;
        }
        .btn-primary { 
            background: var(--btn-primary); 
            color: white; 
        }
        .btn-primary:hover { 
            background: var(--btn-primary-hover); 
        }
        .btn-primary:disabled { 
            background: var(--input-border); 
            cursor: not-allowed; 
        }
        .btn-secondary { 
            background: var(--btn-secondary); 
            color: var(--btn-secondary-text); 
            margin-top: 10px; 
        }
        .btn-secondary:hover { 
            background: var(--input-border); 
        }
        .message {
            text-align: center;
            margin-top: 15px;
            padding: 10px;
            border-radius: 8px;
            font-size: 14px;
            display: none;
        }
        .message.error { 
            background: var(--error-bg); 
            color: var(--error-text); 
            display: block;
        }
        .message.success { 
            background: var(--success-bg); 
            color: var(--success-text); 
            display: block;
        }
        .password-strength {
            height: 4px;
            background: var(--input-border);
            border-radius: 2px;
            margin-top: 8px;
            overflow: hidden;
        }
        .password-strength-bar {
            height: 100%;
            width: 0%;
            transition: 0.3s;
        }
        .strength-weak { background: var(--strength-weak); width: 33%; }
        .strength-medium { background: var(--strength-medium); width: 66%; }
        .strength-strong { background: var(--strength-strong); width: 100%; }
        .requirements {
            font-size: 12px;
            color: var(--text-secondary);
            margin-top: 10px;
            padding: 10px;
            background: var(--badge-bg);
            border-radius: 8px;
        }
        .requirements div {
            margin: 4px 0;
        }
        .req-met { color: var(--req-met); }
        .req-unmet { color: var(--req-unmet); }
    </style>
</head>
<body>
    <!-- Theme Toggle Button -->
    <button class="theme-toggle" onclick="toggleTheme()" id="themeToggle">
        🌙
    </button>

    <div class="container">
        <div class="card">
            <div class="header">
                <h1>🔐 Ganti Password</h1>
                <p>Pastikan password baru aman dan mudah diingat</p>
            </div>

            <div class="user-badge">
                <strong id="userName">Loading...</strong>
                <small id="userInfo">-</small>
            </div>

            <form id="changePasswordForm" onsubmit="return false;">
                <div class="input-group">
                    <label for="oldPassword">Password Lama</label>
                    <div class="password-input-wrapper">
                        <input 
                            type="password" 
                            id="oldPassword" 
                            placeholder="Masukkan password lama"
                            required
                        />
                        <button type="button" class="toggle-password" onclick="togglePassword('oldPassword')" tabindex="-1">
                            👁️
                        </button>
                    </div>
                </div>

                <div class="input-group">
                    <label for="newPassword">Password Baru</label>
                    <div class="password-input-wrapper">
                        <input 
                            type="password" 
                            id="newPassword" 
                            placeholder="Minimal 6 karakter"
                            required
                            oninput="checkPasswordStrength()"
                        />
                        <button type="button" class="toggle-password" onclick="togglePassword('newPassword')" tabindex="-1">
                            👁️
                        </button>
                    </div>
                    <div class="password-strength">
                        <div id="strengthBar" class="password-strength-bar"></div>
                    </div>
                    <div class="password-hint">Minimal 6 karakter</div>
                </div>

                <div class="input-group">
                    <label for="confirmPassword">Konfirmasi Password Baru</label>
                    <div class="password-input-wrapper">
                        <input 
                            type="password" 
                            id="confirmPassword" 
                            placeholder="Ketik ulang password baru"
                            required
                            oninput="checkPasswordMatch()"
                        />
                        <button type="button" class="toggle-password" onclick="togglePassword('confirmPassword')" tabindex="-1">
                            👁️
                        </button>
                    </div>
                </div>

                <div class="requirements">
                    <div id="req-length" class="req-unmet">✗ Minimal 6 karakter</div>
                    <div id="req-match" class="req-unmet">✗ Password harus sama</div>
                </div>

                <button 
                    type="submit" 
                    class="btn-primary" 
                    id="submitBtn"
                    onclick="changePassword()"
                >
                    Ganti Password
                </button>
                
                <button 
                    type="button" 
                    class="btn-secondary" 
                    onclick="goBack()"
                >
                    Kembali
                </button>

                <div id="message" class="message"></div>
            </form>
        </div>
    </div>

    <script>
        let user = null;

        // Initialize
        document.addEventListener('DOMContentLoaded', () => {
            // Load saved theme
            const savedTheme = localStorage.getItem('theme') || 'light';
            document.documentElement.setAttribute('data-theme', savedTheme);
            updateThemeIcon(savedTheme);

            const userStr = localStorage.getItem('user');
            if (!userStr) {
                window.location.href = '/';
                return;
            }
            user = JSON.parse(userStr);
            
            // Display user info
            if (user.isBuffer) {
                document.getElementById('userName').textContent = user.namaBuffer;
                document.getElementById('userInfo').textContent = 'NIK KTP: ' + user.nikKtp;
            } else {
                document.getElementById('userName').textContent = user.nama;
                document.getElementById('userInfo').textContent = 'NIK OMS: ' + user.nik;
            }
        });

        function toggleTheme() {
            const currentTheme = document.documentElement.getAttribute('data-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            
            document.documentElement.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
            updateThemeIcon(newTheme);
        }

        function updateThemeIcon(theme) {
            const themeToggle = document.getElementById('themeToggle');
            themeToggle.textContent = theme === 'dark' ? '☀️' : '🌙';
        }

        function checkPasswordStrength() {
            const password = document.getElementById('newPassword').value;
            const bar = document.getElementById('strengthBar');
            const lengthReq = document.getElementById('req-length');
            
            // Remove all strength classes
            bar.className = 'password-strength-bar';
            
            if (password.length >= 6) {
                lengthReq.className = 'req-met';
                lengthReq.innerHTML = '✓ Minimal 6 karakter';
                
                if (password.length < 8) {
                    bar.classList.add('strength-weak');
                } else if (password.length < 12) {
                    bar.classList.add('strength-medium');
                } else {
                    bar.classList.add('strength-strong');
                }
            } else {
                lengthReq.className = 'req-unmet';
                lengthReq.innerHTML = '✗ Minimal 6 karakter';
            }
            
            checkPasswordMatch();
        }

        function checkPasswordMatch() {
            const newPassword = document.getElementById('newPassword').value;
            const confirmPassword = document.getElementById('confirmPassword').value;
            const matchReq = document.getElementById('req-match');
            const confirmInput = document.getElementById('confirmPassword');
            
            if (confirmPassword.length > 0) {
                if (newPassword === confirmPassword) {
                    matchReq.className = 'req-met';
                    matchReq.innerHTML = '✓ Password cocok';
                    confirmInput.classList.remove('error');
                } else {
                    matchReq.className = 'req-unmet';
                    matchReq.innerHTML = '✗ Password tidak sama';
                    confirmInput.classList.add('error');
                }
            } else {
                matchReq.className = 'req-unmet';
                matchReq.innerHTML = '✗ Password harus sama';
                confirmInput.classList.remove('error');
            }
        }

        function showMessage(text, isError = false) {
            const msg = document.getElementById('message');
            msg.textContent = text;
            msg.className = 'message ' + (isError ? 'error' : 'success');
        }

        function hideMessage() {
            document.getElementById('message').style.display = 'none';
        }

        async function changePassword() {
            hideMessage();
            
            const oldPassword = document.getElementById('oldPassword').value.trim();
            const newPassword = document.getElementById('newPassword').value.trim();
            const confirmPassword = document.getElementById('confirmPassword').value.trim();
            const submitBtn = document.getElementById('submitBtn');

            // Validation
            if (!oldPassword || !newPassword || !confirmPassword) {
                showMessage('Semua field harus diisi', true);
                return;
            }

            if (newPassword.length < 6) {
                showMessage('Password baru minimal 6 karakter', true);
                return;
            }

            if (newPassword !== confirmPassword) {
                showMessage('Password baru dan konfirmasi tidak sama', true);
                return;
            }

            if (oldPassword === newPassword) {
                showMessage('Password baru harus berbeda dengan password lama', true);
                return;
            }

            // Disable button and show loading
            submitBtn.disabled = true;
            submitBtn.textContent = '⏳ Memproses...';

            try {
                const nik = user.isBuffer ? user.nikKtp : user.nik;
                
                const res = await fetch('/api/change-password', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        nik: nik,
                        oldPassword: oldPassword,
                        newPassword: newPassword
                    })
                });

                const data = await res.json();
                
                if (data.error) {
                    throw new Error(data.error);
                }

                if (data.success) {
                    showMessage('✅ Password berhasil diubah! Silakan login ulang...', false);
                    
                    // Clear user data and redirect to login after 2 seconds
                    setTimeout(() => {
                        localStorage.removeItem('user');
                        window.location.href = '/';
                    }, 2000);
                } else {
                    throw new Error('Gagal mengubah password');
                }

            } catch (e) {
                showMessage('❌ ' + e.message, true);
                submitBtn.disabled = false;
                submitBtn.textContent = 'Ganti Password';
            }
        }

        function goBack() {
            window.location.href = '/absen';
        }

        function togglePassword(inputId) {
            const input = document.getElementById(inputId);
            const button = input.nextElementSibling;
            
            if (input.type === 'password') {
                input.type = 'text';
                button.textContent = '🙈';
            } else {
                input.type = 'password';
                button.textContent = '👁️';
            }
        }

        // Enter key support
        document.getElementById('confirmPassword').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                changePassword();
            }
        });
    </script>
</body>
</html>`;
}

// ============================================================================
// SECTION 10: PWA MANIFEST & SERVICE WORKER
// ============================================================================

function getManifest() {
    // Generate proper PWA icons (simple colored squares for now)
    // 192x192 icon (required for PWA)
    const icon192 = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='192' height='192'%3E%3Crect width='192' height='192' fill='%23667eea'/%3E%3Ctext x='96' y='120' font-size='80' text-anchor='middle' fill='white' font-family='Arial'%3EP%3C/text%3E%3C/svg%3E";

    // 512x512 icon (required for Android)
    const icon512 = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='512' height='512'%3E%3Crect width='512' height='512' fill='%23667eea'/%3E%3Ctext x='256' y='320' font-size='200' text-anchor='middle' fill='white' font-family='Arial'%3EP%3C/text%3E%3C/svg%3E";

    return JSON.stringify({
        "name": "Presensi Karyawan",
        "short_name": "Presensi",
        "description": "Aplikasi Presensi Karyawan dengan Foto dan Lokasi",
        "start_url": "./",
        "scope": "./",
        "display": "standalone",
        "background_color": "#667eea",
        "theme_color": "#667eea",
        "orientation": "portrait-primary",
        "categories": ["productivity", "business"],
        "icons": [
            {
                "src": "https://imglink.io/i/f33ff29d-90ec-4e62-ae67-95fbd9afad95.png",
                "sizes": "192x192",
                "type": "image/png",
                "purpose": "any"
            },
            {
                "src": icon192,
                "sizes": "192x192",
                "type": "image/svg+xml",
                "purpose": "maskable"
            },
            {
                "src": "https://imglink.io/i/0ad312c8-2b7f-4de1-ab84-771ffbe19a36.png",
                "sizes": "512x512",
                "type": "image/png",
                "purpose": "any"
            },
            {
                "src": icon512,
                "sizes": "512x512",
                "type": "image/svg+xml",
                "purpose": "maskable"
            }
        ],
        "screenshots": [],
        "prefer_related_applications": false
    });
}

function getServiceWorker() {
    return `
const CACHE_NAME = 'presensi-v1';
const urlsToCache = [
    '/',
    '/absen',
    '/dashboard',
    '/manifest.json'
];

self.addEventListener('install', function(event) {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(function(cache) {
                return cache.addAll(urlsToCache);
            })
            .then(function() {
                return self.skipWaiting();
            })
    );
});

self.addEventListener('activate', function(event) {
    event.waitUntil(
        caches.keys().then(function(cacheNames) {
            return Promise.all(
                cacheNames.map(function(cacheName) {
                    if (cacheName !== CACHE_NAME) {
                        return caches.delete(cacheName);
                    }
                })
            );
        }).then(function() {
            return self.clients.claim();
        })
    );
});

self.addEventListener('fetch', function(event) {
    // Network-first strategy for API calls
    if (event.request.url.includes('/api/')) {
        event.respondWith(
            fetch(event.request)
                .catch(function() {
                    return new Response(
                        JSON.stringify({ error: 'Offline - tidak dapat terhubung ke server' }),
                        { headers: { 'Content-Type': 'application/json' } }
                    );
                })
        );
        return;
    }

    // Cache-first strategy for static assets
    event.respondWith(
        caches.match(event.request)
            .then(function(response) {
                if (response) {
                    return response;
                }
                return fetch(event.request)
                    .then(function(response) {
                        // Don't cache if not a success response
                        if (!response || response.status !== 200 || response.type === 'error') {
                            return response;
                        }
                        
                        const responseToCache = response.clone();
                        caches.open(CACHE_NAME)
                            .then(function(cache) {
                                cache.put(event.request, responseToCache);
                            });
                        
                        return response;
                    });
            })
    );
});
`;
}