package com.example.aptback.controller;

import cn.hutool.core.io.FileUtil;
import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.core.conditions.update.LambdaUpdateWrapper;
import com.example.aptback.common.Result;
import com.example.aptback.entity.GenerationRequest;
import com.example.aptback.entity.User;
import com.example.aptback.mapper.GenerationRequestMapper;
import com.example.aptback.service.GenerationService;
import com.example.aptback.utils.TokenUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

@RestController
@RequestMapping("/generation")
public class GenerationRequestController {

    private static final String REQ_DIR = System.getProperty("user.dir") + File.separator
            + "files" + File.separator + "generation-requests";

    @Autowired
    private GenerationRequestMapper mapper;
    @Autowired
    private com.example.aptback.mapper.UserMapper userMapper;
    @Autowired
    private GenerationService generationService;

    /** 上传参考来源(目前仅 APT 报告 PDF,流量/样本待开发) */
    @PostMapping("/upload")
    public Result upload(@RequestParam("file") MultipartFile file) {
        User currentUser = TokenUtils.getCurrentUser();
        if (currentUser == null) {
            return Result.error("401", "请先登录");
        }
        String original = file.getOriginalFilename();
        if (original == null || !original.toLowerCase().endsWith(".pdf")) {
            return Result.error("500", "目前仅支持 APT 报告(PDF)格式,流量/样本分析待开发");
        }
        String safe = original.replaceAll("[^A-Za-z0-9._-]", "_");
        if (safe.isEmpty()) safe = "report.pdf";
        String fileName = currentUser.getUserName() + "_" + System.currentTimeMillis() + "_" + safe;
        try {
            FileUtil.mkdir(REQ_DIR);
            FileUtil.writeBytes(file.getBytes(), REQ_DIR + File.separator + fileName);
        } catch (IOException e) {
            return Result.error("500", "上传失败:" + e.getMessage());
        }
        return Result.success(fileName);
    }

    /** 提交生成申请:落库后立即异步触发生成引擎 */
    @PostMapping("/submit")
    public Result submit(@RequestBody GenerationRequest req) {
        User currentUser = TokenUtils.getCurrentUser();
        if (currentUser == null) {
            return Result.error("401", "请先登录");
        }
        if (req.getGenEvents() == null || req.getGenEvents().trim().isEmpty()) {
            return Result.error("500", "请填写要生成的事件");
        }
        req.setUserId(currentUser.getId());
        req.setUserName(currentUser.getUserName());
        req.setStatus("生成中");
        req.setGenStatus(0);
        mapper.insert(req);

        // 确定生成输入:有附件用 PDF,无附件把事件描述写成 TXT(脚本原生支持)
        File input = null;
        if (req.getSourceFile() != null && !req.getSourceFile().trim().isEmpty()) {
            File f = new File(REQ_DIR, req.getSourceFile().trim());
            input = f.exists() ? f : null;
        }
        if (input == null) {
            input = generationService.writeEventsAsInput(currentUser.getUserName(), req.getGenEvents());
        }
        if (input == null || !input.exists()) {
            mapper.update(null, new LambdaUpdateWrapper<GenerationRequest>()
                    .eq(GenerationRequest::getId, req.getId())
                    .set(GenerationRequest::getGenStatus, 2)
                    .set(GenerationRequest::getStatus, "生成失败")
                    .set(GenerationRequest::getGenLog, "生成输入文件不可用"));
            return Result.error("500", "生成输入文件不可用,请重试");
        }
        generationService.triggerAsync(req, input);
        return Result.success(req.getId());
    }

    /** 本人申请列表(个人中心"我的数据集") */
    @GetMapping("/mylist")
    public Result mylist() {
        User currentUser = TokenUtils.getCurrentUser();
        if (currentUser == null) {
            return Result.error("401", "请先登录");
        }
        List<GenerationRequest> list = mapper.selectList(
                new LambdaQueryWrapper<GenerationRequest>()
                        .eq(GenerationRequest::getUserId, currentUser.getId())
                        .orderByDesc(GenerationRequest::getId));
        return Result.success(list);
    }

    /** 打包下载本人已生成成功的数据集(zip) */
    @GetMapping("/download")
    public void download(@RequestParam Integer id,
                         @RequestParam(value = "token", required = false) String queryToken,
                         HttpServletRequest request,
                         HttpServletResponse response) throws IOException {
        User currentUser = TokenUtils.getCurrentUser();
        // window.open 下载无法带自定义header,支持 ?token= 查询参数(拦截器同样认可)
        if (currentUser == null && queryToken != null && !queryToken.isEmpty()) {
            try {
                String userId = com.auth0.jwt.JWT.decode(queryToken).getAudience().get(0);
                currentUser = userMapper.selectById(Integer.valueOf(userId));
            } catch (Exception ignore) {
                currentUser = null;
            }
        }
        if (currentUser == null) {
            response.setStatus(401);
            return;
        }
        GenerationRequest req = mapper.selectById(id);
        if (req == null || !currentUser.getId().equals(req.getUserId())) {
            response.setStatus(404);
            return;
        }
        if (req.getGenStatus() == null || req.getGenStatus() != 1 || req.getOutputPath() == null) {
            response.setStatus(404);
            response.setContentType("application/json;charset=utf-8");
            response.getWriter().write("{\"code\":\"404\",\"msg\":\"数据集尚未生成成功\"}");
            return;
        }
        File dir = new File(System.getProperty("user.dir"), req.getOutputPath());
        if (!dir.isDirectory()) {
            response.setStatus(404);
            response.setContentType("application/json;charset=utf-8");
            response.getWriter().write("{\"code\":\"404\",\"msg\":\"生成目录缺失\"}");
            return;
        }
        String zipName = dir.getName() + ".zip";
        response.setContentType("application/zip");
        response.setHeader("Content-Disposition", "attachment; filename=\"" + zipName + "\"");
        try (ZipOutputStream zos = new ZipOutputStream(response.getOutputStream(), StandardCharsets.UTF_8)) {
            zipDir(dir.toPath().getParent(), dir.toPath(), zos);
            zos.finish();
        }
    }

    /** 递归打包;entryName 以剧本目录名为根 */
    private void zipDir(Path parent, Path current, ZipOutputStream zos) throws IOException {
        try (var stream = Files.list(current)) {
            for (Path p : (Iterable<Path>) stream::iterator) {
                if (Files.isDirectory(p)) {
                    zipDir(parent, p, zos);
                } else {
                    String entryName = parent.relativize(p).toString().replace('\\', '/');
                    zos.putNextEntry(new ZipEntry(entryName));
                    try (FileInputStream fis = new FileInputStream(p.toFile())) {
                        fis.transferTo(zos);
                    }
                    zos.closeEntry();
                }
            }
        }
    }
}
