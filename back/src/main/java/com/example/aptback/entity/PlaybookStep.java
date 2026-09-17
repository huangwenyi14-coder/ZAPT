package com.example.aptback.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableName;

@TableName("playbook_step")
public class PlaybookStep {
    @TableId(type = IdType.AUTO)
    private Integer id;
    private Integer playbookId;
    private Integer stepNo;
    private String storylineId;
    private String actor;
    @TableField("`system`")
    private String system;
    private String activity;
    private String eventTypes;
    private String tacticId;
    private String tacticName;
    private String techniques;

    public Integer getId() { return id; }
    public void setId(Integer id) { this.id = id; }
    public Integer getPlaybookId() { return playbookId; }
    public void setPlaybookId(Integer playbookId) { this.playbookId = playbookId; }
    public Integer getStepNo() { return stepNo; }
    public void setStepNo(Integer stepNo) { this.stepNo = stepNo; }
    public String getStorylineId() { return storylineId; }
    public void setStorylineId(String storylineId) { this.storylineId = storylineId; }
    public String getActor() { return actor; }
    public void setActor(String actor) { this.actor = actor; }
    public String getSystem() { return system; }
    public void setSystem(String system) { this.system = system; }
    public String getActivity() { return activity; }
    public void setActivity(String activity) { this.activity = activity; }
    public String getEventTypes() { return eventTypes; }
    public void setEventTypes(String eventTypes) { this.eventTypes = eventTypes; }
    public String getTacticId() { return tacticId; }
    public void setTacticId(String tacticId) { this.tacticId = tacticId; }
    public String getTacticName() { return tacticName; }
    public void setTacticName(String tacticName) { this.tacticName = tacticName; }
    public String getTechniques() { return techniques; }
    public void setTechniques(String techniques) { this.techniques = techniques; }
}
