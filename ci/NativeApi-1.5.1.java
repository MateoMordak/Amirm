package ir.dinavo.fraudwatch;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.Uri;

import org.json.JSONObject;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Lightweight native REST client. Android renders UI locally; WordPress only supplies JSON. */
final class NativeApi {
    private static final String REST_ROOT = "https://dinavo.ir/wp-json/irs-spect/v1/native";
    private static final String ALT_ROOT = "https://dinavo.ir/?rest_route=/irs-spect/v1/native";
    static final String APP_CONFIG = "https://dinavo.ir/irscheck/?dga_app_api=app-config";
    private static final String PREFS = "irs_spect";
    private static final String TOKEN = "auth_token";
    private static final ExecutorService EXECUTOR = Executors.newFixedThreadPool(3);

    interface Callback { void done(Result result); }

    static final class Result {
        final int code;
        final JSONObject json;
        final String error;
        final boolean readable;
        Result(int code, JSONObject json, String error) { this(code, json, error, json != null); }
        Result(int code, JSONObject json, String error, boolean readable) {
            this.code=code; this.json=json; this.error=error == null ? "" : error; this.readable=readable;
        }
        boolean ok() { return code >= 200 && code < 300 && json != null; }
        String message(String fallback) {
            if (json != null) {
                String m=json.optString("message", "");
                if (m.isEmpty()) {
                    JSONObject data=json.optJSONObject("data");
                    if (data!=null) m=data.optString("message", "");
                }
                String wpCode=json.optString("code", "");
                if ("rest_no_route".equals(wpCode)) {
                    return "API اپ فعال نیست. افزونه IRS Spect 1.3.82 یا جدیدتر را نصب و فعال کنید.";
                }
                if (!m.isEmpty()) return m;
            }
            return error.isEmpty() ? fallback : error;
        }
    }

    private final Context context;
    NativeApi(Context context) { this.context=context.getApplicationContext(); }

    String token() { return prefs().getString(TOKEN, ""); }
    boolean signedIn() { return !token().isEmpty(); }
    void saveToken(String token) { prefs().edit().putString(TOKEN, token == null ? "" : token).apply(); }
    void clearToken() { prefs().edit().remove(TOKEN).remove("portal_cookie").apply(); }

    void login(String username, String password, Callback callback) {
        JSONObject body=new JSONObject();
        try { body.put("username", username); body.put("password", password); } catch(Exception ignored) { }
        post("/login", body, false, result -> {
            if(result.ok()) {
                String t=result.json.optString("token", "");
                if(!t.isEmpty()) saveToken(t);
            }
            callback.done(result);
        });
    }

    void get(String path, Map<String,String> params, Callback callback) { request("GET", path, params, null, true, callback); }
    void get(String path, Callback callback) { get(path, null, callback); }
    void post(String path, JSONObject body, Callback callback) { post(path, body, true, callback); }
    void post(String path, JSONObject body, boolean authenticated, Callback callback) { request("POST", path, null, body, authenticated, callback); }

    void multipartRelease(Uri apk, Map<String,String> fields, Callback callback) {
        EXECUTOR.execute(() -> {
            Result first = multipartReleaseAttempt(REST_ROOT+"/admin/release", apk, fields);
            if (shouldRetryAlternate(first)) callback.done(multipartReleaseAttempt(ALT_ROOT+"/admin/release", apk, fields));
            else callback.done(first);
        });
    }

    private Result multipartReleaseAttempt(String target, Uri apk, Map<String,String> fields) {
        HttpURLConnection connection=null;
        try {
            String boundary="----IRSSpect"+System.currentTimeMillis();
            connection=(HttpURLConnection)new URL(target).openConnection();
            configure(connection,"POST",true);
            connection.setReadTimeout(45000);
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "multipart/form-data; boundary="+boundary);
            try(OutputStream raw=new BufferedOutputStream(connection.getOutputStream())) {
                for(Map.Entry<String,String> entry:fields.entrySet()) {
                    write(raw,"--"+boundary+"\r\nContent-Disposition: form-data; name=\""+entry.getKey()+"\"\r\n\r\n"+entry.getValue()+"\r\n");
                }
                write(raw,"--"+boundary+"\r\nContent-Disposition: form-data; name=\"apk\"; filename=\"IRS-Spect.apk\"\r\nContent-Type: application/vnd.android.package-archive\r\n\r\n");
                try(InputStream in=context.getContentResolver().openInputStream(apk)) {
                    if(in==null) throw new IllegalStateException("APK unavailable");
                    byte[] buffer=new byte[32*1024]; int n; while((n=in.read(buffer))!=-1) raw.write(buffer,0,n);
                }
                write(raw,"\r\n--"+boundary+"--\r\n"); raw.flush();
            }
            return readResult(connection);
        } catch(Exception e) { return new Result(0,null,"ارتباط با سرور انجام نشد.",false); }
        finally { if(connection!=null) connection.disconnect(); }
    }

    private void request(String method, String path, Map<String,String> params, JSONObject body, boolean authenticated, Callback callback) {
        EXECUTOR.execute(() -> {
            Result first=requestAttempt(method, buildTarget(REST_ROOT,path,params,false), body, authenticated);
            if (shouldRetryAlternate(first)) {
                Result second=requestAttempt(method, buildTarget(ALT_ROOT,path,params,true), body, authenticated);
                callback.done(second);
            } else callback.done(first);
        });
    }

    private Result requestAttempt(String method, String target, JSONObject body, boolean authenticated) {
        HttpURLConnection connection=null;
        try {
            connection=(HttpURLConnection)new URL(target).openConnection();
            configure(connection,method,authenticated);
            if(body!=null) {
                connection.setDoOutput(true);
                connection.setRequestProperty("Content-Type","application/json; charset=utf-8");
                byte[] bytes=body.toString().getBytes(StandardCharsets.UTF_8);
                connection.setFixedLengthStreamingMode(bytes.length);
                try(OutputStream out=connection.getOutputStream()) { out.write(bytes); }
            }
            Result result=readResult(connection);
            if(result.code==401 && authenticated) clearToken();
            return result;
        } catch(Exception e) { return new Result(0,null,"ارتباط با سرور انجام نشد.",false); }
        finally { if(connection!=null) connection.disconnect(); }
    }

    private void configure(HttpURLConnection connection, String method, boolean authenticated) throws Exception {
        connection.setConnectTimeout(8000);
        connection.setReadTimeout(14000);
        connection.setRequestMethod(method);
        connection.setUseCaches(false);
        connection.setRequestProperty("Accept","application/json, text/plain;q=0.9, */*;q=0.1");
        connection.setRequestProperty("Accept-Encoding","identity");
        connection.setRequestProperty("Cache-Control","no-cache, no-store");
        connection.setRequestProperty("Pragma","no-cache");
        connection.setRequestProperty("User-Agent","IRS-Spect-Android/"+MainActivity.APP_VERSION_NAME);
        connection.setRequestProperty("X-IRS-Spect-Client","native-android");
        if(authenticated && !token().isEmpty()) connection.setRequestProperty("Authorization","Bearer "+token());
    }

    private static String buildTarget(String root, String path, Map<String,String> params, boolean alternate) {
        StringBuilder target=new StringBuilder(root).append(path);
        if(params!=null && !params.isEmpty()) {
            target.append(alternate ? '&' : '?'); boolean first=true;
            for(Map.Entry<String,String> e:params.entrySet()) {
                if(!first) target.append('&'); first=false;
                target.append(URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8)).append('=').append(URLEncoder.encode(e.getValue()==null?"":e.getValue(), StandardCharsets.UTF_8));
            }
        }
        return target.toString();
    }

    private static boolean shouldRetryAlternate(Result result) {
        if(result==null) return true;
        if(!result.readable || result.json==null) return true;
        // Retry common rewrite/WAF front-door failures, but never duplicate a normal auth/application response.
        return result.code==404 && "rest_no_route".equals(result.json.optString("code", ""));
    }

    private Result readResult(HttpURLConnection connection) {
        int code=0;
        try {
            code=connection.getResponseCode();
            InputStream stream=code>=200&&code<400?connection.getInputStream():connection.getErrorStream();
            String text=stream==null?"":readUtf8(stream);
            String normalized=normalizeJsonBody(text);
            if(normalized.isEmpty()) return new Result(code,new JSONObject(),"",true);
            JSONObject json=new JSONObject(normalized);
            return new Result(code,json,"",true);
        } catch(Exception e) {
            return new Result(code,null,"پاسخ API معتبر نبود؛ مسیر جایگزین بررسی می‌شود.",false);
        }
    }

    /** Tolerate UTF-8 BOM and harmless PHP notices/whitespace surrounding a JSON object. */
    private static String normalizeJsonBody(String text) {
        if(text==null) return "";
        String s=text.replace("\uFEFF", "").trim();
        if(s.isEmpty()) return "";
        if(s.charAt(0)=='{' && s.charAt(s.length()-1)=='}') return s;
        int start=s.indexOf('{');
        int end=s.lastIndexOf('}');
        if(start>=0 && end>start) return s.substring(start,end+1).trim();
        return s;
    }

    private static String readUtf8(InputStream input) throws Exception {
        try(InputStream in=new BufferedInputStream(input); ByteArrayOutputStream out=new ByteArrayOutputStream()) {
            byte[] buf=new byte[8192]; int n; while((n=in.read(buf))!=-1) out.write(buf,0,n);
            return out.toString("UTF-8");
        }
    }
    private static void write(OutputStream out,String text)throws Exception{out.write(text.getBytes(StandardCharsets.UTF_8));}
    private SharedPreferences prefs(){return context.getSharedPreferences(PREFS,Context.MODE_PRIVATE);}

    static Map<String,String> params(String... values) {
        Map<String,String> result=new LinkedHashMap<>();
        for(int i=0;i+1<values.length;i+=2) result.put(values[i],values[i+1]);
        return result;
    }
}
