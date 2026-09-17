package com.example.aptback.controller;

import cn.hutool.core.io.FileUtil;
import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.core.conditions.update.LambdaUpdateWrapper;
import com.baomidou.mybatisplus.core.metadata.IPage;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.example.aptback.common.Result;
import com.example.aptback.entity.Playbook;
import com.example.aptback.entity.PlaybookApplication;
import com.example.aptback.entity.PlaybookStep;
import com.example.aptback.entity.User;
import com.example.aptback.mapper.PlaybookApplicationMapper;
import com.example.aptback.mapper.PlaybookMapper;
import com.example.aptback.mapper.PlaybookStepMapper;
import com.example.aptback.utils.TokenUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/playbook")
public class PlaybookController {

    private static final String PACKAGE_DIR = System.getProperty("user.dir") + File.separator
            + "files" + File.separator + "dataset-packages";

    @Autowired
    private PlaybookMapper playbookMapper;
    @Autowired
    private PlaybookStepMapper stepMapper;
    @Autowired
    private PlaybookApplicationMapper applicationMapper;

    /** 剧本分页列表,可按组织筛选,按seq_no排序(可下载的置顶) */
    @GetMapping("/selectPage")
    public Result selectPage(@RequestParam Integer pageNum,
                             @RequestParam Integer pageSize,
                             @RequestParam(required = false) String group) {
        Page<Playbook> page = new Page<>(pageNum, pageSize);
        LambdaQueryWrapper<Playbook> qw = new LambdaQueryWrapper<>();
        if (group != null && !group.trim().isEmpty()) {
            qw.eq(Playbook::getThreatGroup, group.trim());
        }
        qw.orderByAsc(Playbook::getSeqNo);
        IPage<Playbook> result = playbookMapper.selectPage(page, qw);
        return Result.success(result);
    }

    /** 组织筛选项 */
    @GetMapping("/groups")
    public Result groups() {
        List<Playbook> all = playbookMapper.selectList(null);
        Map<String, Integer> count = new HashMap<>();
        for (Playbook p : all) {
            count.merge(p.getThreatGroup(), 1, Integer::sum);
        }
        return Result.success(count);
    }

    /** 剧本详情:主表+攻击链步骤+时间线事件 */
    @GetMapping("/selectById")
    public Result selectById(@RequestParam Integer id) {
        Playbook playbook = playbookMapper.selectById(id);
        if (playbook == null) {
            return Result.error("500", "剧本不存在");
        }
        List<PlaybookStep> steps = stepMapper.selectList(
                new LambdaQueryWrapper<PlaybookStep>().eq(PlaybookStep::getPlaybookId, id)
                        .orderByAsc(PlaybookStep::getStepNo));
        Map<String, Object> data = new HashMap<>();
        data.put("playbook", playbook);
        data.put("steps", steps);
        return Result.success(data);
    }

    /** 已开放剧本的整包下载(tar.gz) */
    @GetMapping("/download")
    public void download(@RequestParam Integer id, HttpServletResponse response) throws IOException {
        Playbook playbook = playbookMapper.selectById(id);
        if (playbook == null || playbook.getDownloadable() == null || playbook.getDownloadable() != 1
                || playbook.getPackageName() == null) {
            response.setStatus(404);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write("{\"code\":\"404\",\"msg\":\"该剧本暂未开放下载,请提交申请\"}");
            return;
        }
        File file = new File(PACKAGE_DIR, playbook.getPackageName());
        if (!file.exists()) {
            response.setStatus(404);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write("{\"code\":\"404\",\"msg\":\"数据包文件缺失,请联系管理员\"}");
            return;
        }
        playbookMapper.update(null, new LambdaUpdateWrapper<Playbook>()
                .eq(Playbook::getId, id)
                .setSql("download_count = download_count + 1"));
        response.setContentType("application/gzip");
        response.setHeader(HttpHeaders.CONTENT_DISPOSITION,
                "attachment; filename=\"" + playbook.getPackageName() + "\"");
        response.setContentLengthLong(file.length());
        byte[] bytes = FileUtil.readBytes(file);
        try (OutputStream os = response.getOutputStream()) {
            os.write(bytes);
            os.flush();
        }
    }

    /** 未开放剧本的下载申请(登录后提交,记录待管理员审核) */
    @PostMapping("/apply")
    public Result apply(@RequestBody PlaybookApplication application) {
        User currentUser = TokenUtils.getCurrentUser();
        if (currentUser == null) {
            return Result.error("401", "请先登录");
        }
        if (application.getPlaybookCode() == null || application.getPlaybookCode().trim().isEmpty()) {
            return Result.error("500", "剧本编号不能为空");
        }
        Playbook playbook = playbookMapper.selectOne(
                new LambdaQueryWrapper<Playbook>().eq(Playbook::getCode, application.getPlaybookCode().trim()));
        if (playbook == null) {
            return Result.error("500", "剧本不存在");
        }
        application.setUserId(currentUser.getId());
        application.setStatus("待审核");
        applicationMapper.insert(application);
        return Result.success();
    }
}
