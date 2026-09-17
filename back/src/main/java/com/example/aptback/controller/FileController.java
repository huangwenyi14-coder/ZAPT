package com.example.aptback.controller;

import cn.hutool.core.io.FileUtil;
import com.example.aptback.common.Result;
import com.example.aptback.entity.User;
import com.example.aptback.utils.TokenUtils;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.net.URLEncoder;

@RestController
@RequestMapping("/file")
public class FileController {

    @Value("${server.port}")
    String port;

    private static final String ROOT_PATH =  System.getProperty("user.dir") + File.separator + "files";
    private static final String AVATAR_DIR = "avatars";

    /**
     * 头像上传:存到 files/avatars/{账号}.{扩展名},同一账号重传直接覆盖(天然去重)
     */
    @PostMapping("/uploadAvatar")
    public Result uploadAvatar(MultipartFile file) throws IOException {
        User currentUser = TokenUtils.getCurrentUser();
        if (currentUser == null) {
            return Result.error("401", "请先登录");
        }
        String originalFilename = file.getOriginalFilename();
        String extName = FileUtil.extName(originalFilename);
        if (extName != null) {
            // 扩展名只保留字母数字,防止路径注入
            extName = extName.replaceAll("[^A-Za-z0-9]", "");
        }
        if (extName == null || extName.isEmpty()) {
            extName = "jpg";
        }
        // 文件名即账号,同账号覆盖
        String fileName = AVATAR_DIR + File.separator + currentUser.getUserName() + "." + extName;
        File saveFile = new File(ROOT_PATH + File.separator + fileName);
        FileUtil.mkParentDirs(saveFile);
        file.transferTo(saveFile);
        String url = "http://172.23.111.192:" + port + "/file/download?fileName=" + fileName.replace(File.separatorChar, '/');
        return Result.success(url);
    }

    /**
     * 文件上传
     */
    @PostMapping("/upload")
    public Result upload(MultipartFile file) throws IOException {
        // 文件的原始名称，例如xxx.png
        String originalFilename = file.getOriginalFilename();
        // xxx
        String mainName = FileUtil.mainName(originalFilename);
        // png
        String extName = FileUtil.extName(originalFilename);
        // 文件名只保留字母数字与下划线,避免中文/空格在URL与磁盘间编码不一致导致裂图
        String safeMain = mainName.replaceAll("[^A-Za-z0-9_-]", "");
        if (safeMain.isEmpty()) {
            safeMain = "file";
        }
        originalFilename = safeMain + "." + extName;
        if (!FileUtil.exist(ROOT_PATH)) {
            // 如果当前文件的父级目录不存在，就创建
            FileUtil.mkdir(ROOT_PATH);
        }
        // 如果当前上传的文件已经存在了，那么这个时候我就要重名一个文件名称
        if (FileUtil.exist(ROOT_PATH + File.separator + originalFilename)) {
            originalFilename = System.currentTimeMillis() + "_" + safeMain + "." + extName;
        }
        File saveFile = new File(ROOT_PATH + File.separator + originalFilename);
        // 存储文件到本地的磁盘里面
        file.transferTo(saveFile);
        // 文件地址
        String url = "http://172.23.111.192:" + port + "/file/download?fileName=" + originalFilename;
        return Result.success(url);
    }

    /**
     * 下载文件
     */
    @GetMapping("/download")
    public void download(@RequestParam String fileName, HttpServletResponse response) throws IOException {
        // 防路径穿越:不允许相对路径分量
        if (fileName.contains("..")) {
            return;
        }
        // 附件下载
        response.addHeader("Content-Disposition", "attachment;filename=" + URLEncoder.encode(fileName, "UTF-8"));
        // 根据扩展名设置Content-Type,否则浏览器可能拒绝在<img>中渲染
        String mimeType = FileUtil.getMimeType(fileName);
        if (mimeType != null) {
            response.setContentType(mimeType);
        }
        // 文件路径
        String filePath = ROOT_PATH  + File.separator + fileName.replace("/", File.separator);
        if (!FileUtil.exist(filePath)) {
            return;
        }
        byte[] bytes = FileUtil.readBytes(filePath);
        ServletOutputStream outputStream = response.getOutputStream();
        try {
            outputStream.write(bytes);
            outputStream.flush();
            outputStream.close();
        } catch (Exception e){
            e.printStackTrace();
        }
    }
}