// =============================================
// 🏠 HOME - HIỂN THỊ TOÀN BỘ CHỨC NĂNG API (JSON)
// =============================================

export async function handler() {
  const apis = {
    "/home": "Hiển thị toàn bộ chức năng và hướng dẫn sử dụng API",
    "/checksql": "Kiểm tra truy vấn SQL Injection (GET hoặc POST)",
    "/dump": "Xuất, sao lưu hoặc tải dữ liệu hệ thống",
    "/status": "Kiểm tra trạng thái hoạt động của API",
    "/fetch": "Lấy dữ liệu từ một URL hoặc API khác",
    "/report": "Gửi báo cáo lỗi, lỗ hổng hoặc phản hồi hệ thống",
  };

  const huongdan = {
    checksql: {
      method: "GET / POST",
      example: "/checksql?query=SELECT * FROM users",
      note: "Dò SQL Injection và kiểm tra cú pháp truy vấn."
    },
    dump: {
      method: "GET",
      example: "/dump?table=users",
      note: "Xuất dữ liệu hoặc kiểm tra thông tin bảng (demo)."
    },
    status: {
      method: "GET",
      example: "/status",
      note: "Trả trạng thái hoạt động và thời gian phản hồi."
    },
    fetch: {
      method: "GET",
      example: "/fetch?url=https://example.com",
      note: "Lấy dữ liệu HTML hoặc JSON từ URL bên ngoài."
    },
    report: {
      method: "POST",
      example: "/report",
      body: { message: "Phát hiện lỗi SQL injection" },
      note: "Gửi báo cáo bảo mật hoặc phản hồi lỗi."
    }
  };

  const response = {
    project: "API SQLMap Netlify",
    author: "truyentranh210",
    version: "1.0.0",
    last_update: new Date().toISOString(),
    description: "API kiểm tra bảo mật & thao tác dữ liệu dạng SQL demo trên Netlify Functions.",
    endpoints: apis,
    usage: huongdan
  };

  return {
    statusCode: 200,
    headers: { "Content-Type": "application/json; charset=utf-8" },
    body: JSON.stringify(response, null, 2)
  };
}
