package com.example.aptback.service;

import cn.hutool.core.io.FileUtil;
import com.baomidou.mybatisplus.core.conditions.update.LambdaUpdateWrapper;
import com.example.aptback.entity.GenerationRequest;
import com.example.aptback.mapper.GenerationRequestMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * 数据生成服务:调用 scripts/APTChain-Benchmark 的 generate_from_report.py
 * 以 uv run 方式执行(环境由 uv 按 uv.lock 自管理),输出到 files/generations/{用户}/{目录}
 */
@Service
public class GenerationService {

    private static final DateTimeFormatter DIR_TS = DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss");
    private static final long TIMEOUT_MINUTES = 30;
    private static final int LOG_KEEP = 900;

    @Value("${eforge.uv-path}")
    private String uvPath;
    @Value("${eforge.home}")
    private String eforgeHome;
    @Value("${eforge.key-file}")
    private String keyFile;
    @Value("${eforge.model:}")
    private String model;
    @Value("${eforge.base-url:}")
    private String baseUrl;

    // 最多同时跑2个生成任务,其余排队,防止大量并发把机器/API打满
    private final ExecutorService executor = Executors.newFixedThreadPool(2);

    @org.springframework.beans.factory.annotation.Autowired
    private GenerationRequestMapper mapper;

    /** 触发异步生成:req 已入库,id 有效;inputFile 为 PDF/TXT 输入文件 */
    public void triggerAsync(GenerationRequest req, File inputFile) {
        executor.submit(() -> run(req, inputFile));
    }

    private void run(GenerationRequest req, File inputFile) {
        String baseDir = System.getProperty("user.dir") + File.separator + "files" + File.separator
                + "generations" + File.separator + safeDir(req.getUserName());
        String dirName = safeDir(brief(req.getGenEvents(), 16)) + "_" + LocalDateTime.now().format(DIR_TS)
                + "-" + Integer.toHexString((int)(Math.random() * 0xfff));
        File outputDir = new File(baseDir, dirName);
        FileUtil.mkParentDirs(outputDir);
        String relPath = "files/generations/" + safeDir(req.getUserName()) + "/" + dirName;

        update(req.getId(), 0, relPath, null);

        List<String> cmd = new ArrayList<>();
        cmd.add(uvPath);
        cmd.add("run");
        cmd.add("python");
        cmd.add("scripts/generate_from_report.py");
        cmd.add(inputFile.getAbsolutePath());
        cmd.add("--output");
        cmd.add(outputDir.getAbsolutePath());
        cmd.add("--api-key-file");
        cmd.add(new File(System.getProperty("user.dir"), keyFile).getAbsolutePath());
        if (model != null && !model.trim().isEmpty()) {
            cmd.add("--model");
            cmd.add(model.trim());
        }
        if (baseUrl != null && !baseUrl.trim().isEmpty()) {
            cmd.add("--base-url");
            cmd.add(baseUrl.trim());
        }
        cmd.add("--force");

        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.directory(new File(System.getProperty("user.dir"), eforgeHome));
        pb.redirectErrorStream(true);
        // Windows 下控制台输出为系统编码,避免中文乱码
        pb.environment().put("PYTHONIOENCODING", "utf-8");

        StringBuilder log = new StringBuilder();
        try {
            Process proc = pb.start();
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(proc.getInputStream(), guessConsoleCharset()));
            String line;
            while ((line = reader.readLine()) != null) {
                synchronized (log) {
                    if (log.length() > 0) log.append('\n');
                    log.append(line);
                    // 只保留尾部,防内存膨胀
                    if (log.length() > LOG_KEEP * 4) log.delete(0, log.length() - LOG_KEEP * 4);
                }
            }
            boolean finished = proc.waitFor(TIMEOUT_MINUTES, TimeUnit.MINUTES);
            if (!finished) {
                proc.destroyForcibly();
                update(req.getId(), 2, relPath, "生成超时(" + TIMEOUT_MINUTES + "分钟)\n" + tail(log));
                return;
            }
            // 完整日志落盘:输出目录旁 {目录名}.log,不截断,便于事后排查
            try {
                java.nio.file.Files.write(outputDir.getParentFile().toPath().resolve(dirName + ".log"),
                        log.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
            } catch (Exception ignore) {
            }
            if (proc.exitValue() == 0) {
                update(req.getId(), 1, relPath, tail(log));
            } else {
                update(req.getId(), 2, relPath, "退出码 " + proc.exitValue() + "\n" + tail(log));
            }
        } catch (Exception e) {
            update(req.getId(), 2, relPath, "执行异常:" + e.getClass().getSimpleName() + " " + e.getMessage()
                    + "\n" + tail(log));
        }
    }

    private void update(Integer id, int status, String relPath, String log) {
        String cut = log == null ? null : (log.length() > 1000 ? log.substring(log.length() - 1000) : log);
        mapper.update(null, new LambdaUpdateWrapper<GenerationRequest>()
                .eq(GenerationRequest::getId, id)
                .set(GenerationRequest::getGenStatus, status)
                .set(GenerationRequest::getOutputPath, relPath)
                .set(GenerationRequest::getGenLog, cut)
                .set(GenerationRequest::getStatus, status == 1 ? "已生成" : status == 2 ? "生成失败" : "生成中"));
    }

    private String tail(StringBuilder sb) {
        synchronized (sb) {
            int len = sb.length();
            return len > LOG_KEEP ? sb.substring(len - LOG_KEEP) : sb.toString();
        }
    }

    /** 目录名安全化:仅保留中英数字与连字符 */
    private String safeDir(String s) {
        if (s == null) return "unnamed";
        String r = s.replaceAll("[\\\\/:*?\"<>|\\s.]+", "-").replaceAll("-+", "-").replaceAll("^-|-$", "");
        return r.isEmpty() ? "unnamed" : r;
    }

    private String brief(String s, int n) {
        if (s == null) return "gen";
        String t = s.replaceAll("[\\r\\n\\t ]+", " ").trim();
        return t.length() > n ? t.substring(0, n) : t;
    }

    private Charset guessConsoleCharset() {
        // Windows 控制台默认 GBK;脚本已设置 PYTHONIOENCODING=utf-8,统一按 UTF-8 读
        return StandardCharsets.UTF_8;
    }

    /** 供无附件申请生成输入 TXT(脚本原生支持 .txt 输入) */
    public File writeEventsAsInput(String userName, String events) {
        try {
            File dir = new File(System.getProperty("user.dir") + File.separator + "files"
                    + File.separator + "generation-requests");
            FileUtil.mkParentDirs(dir);
            Path p = dir.toPath().resolve(safeDir(userName) + "_" + System.currentTimeMillis() + "_input.txt");
            Files.write(p, events.getBytes(StandardCharsets.UTF_8));
            return p.toFile();
        } catch (Exception e) {
            return null;
        }
    }
}
