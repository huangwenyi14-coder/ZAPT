package com.example.aptback.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Date;

@TableName("playbook")
public class Playbook {
    @TableId(type = IdType.AUTO)
    private Integer id;
    private String code;
    private Integer seqNo;
    @JsonFormat(pattern = "yyyy-MM-dd", timezone = "GMT+8")
    private Date attackDate;
    private String threatGroup;
    private String description;
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String descriptionEn;
    private String sourceReport;
    private Integer stepCount;
    private Integer eventCount;
    private Integer redHerringCount;
    private Integer hostCount;
    private Integer userCount;
    private Integer techniqueCount;
    private Integer artifactCount;
    private Integer fileCount;
    private Integer dataSizeMb;
    private String packageName;
    private Integer downloadable;
    private Integer downloadCount;
    private String dataPath;
    private String scenarioPath;
    private String defenseFile;
    private String techniqueIds;
    private String tacticNames;
    private Date createdAt;

    public Integer getId() { return id; }
    public void setId(Integer id) { this.id = id; }
    public String getCode() { return code; }
    public void setCode(String code) { this.code = code; }
    public Integer getSeqNo() { return seqNo; }
    public void setSeqNo(Integer seqNo) { this.seqNo = seqNo; }
    public Date getAttackDate() { return attackDate; }
    public void setAttackDate(Date attackDate) { this.attackDate = attackDate; }
    public String getThreatGroup() { return threatGroup; }
    public void setThreatGroup(String threatGroup) { this.threatGroup = threatGroup; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public String getDescriptionEn() { return descriptionEn; }
    public void setDescriptionEn(String descriptionEn) { this.descriptionEn = descriptionEn; }
    public String getSourceReport() { return sourceReport; }
    public void setSourceReport(String sourceReport) { this.sourceReport = sourceReport; }
    public Integer getStepCount() { return stepCount; }
    public void setStepCount(Integer stepCount) { this.stepCount = stepCount; }
    public Integer getEventCount() { return eventCount; }
    public void setEventCount(Integer eventCount) { this.eventCount = eventCount; }
    public Integer getRedHerringCount() { return redHerringCount; }
    public void setRedHerringCount(Integer redHerringCount) { this.redHerringCount = redHerringCount; }
    public Integer getHostCount() { return hostCount; }
    public void setHostCount(Integer hostCount) { this.hostCount = hostCount; }
    public Integer getUserCount() { return userCount; }
    public void setUserCount(Integer userCount) { this.userCount = userCount; }
    public Integer getTechniqueCount() { return techniqueCount; }
    public void setTechniqueCount(Integer techniqueCount) { this.techniqueCount = techniqueCount; }
    public Integer getArtifactCount() { return artifactCount; }
    public void setArtifactCount(Integer artifactCount) { this.artifactCount = artifactCount; }
    public Integer getFileCount() { return fileCount; }
    public void setFileCount(Integer fileCount) { this.fileCount = fileCount; }
    public Integer getDataSizeMb() { return dataSizeMb; }
    public void setDataSizeMb(Integer dataSizeMb) { this.dataSizeMb = dataSizeMb; }
    public String getPackageName() { return packageName; }
    public void setPackageName(String packageName) { this.packageName = packageName; }
    public Integer getDownloadable() { return downloadable; }
    public void setDownloadable(Integer downloadable) { this.downloadable = downloadable; }
    public Integer getDownloadCount() { return downloadCount; }
    public void setDownloadCount(Integer downloadCount) { this.downloadCount = downloadCount; }
    public String getDataPath() { return dataPath; }
    public void setDataPath(String dataPath) { this.dataPath = dataPath; }
    public String getScenarioPath() { return scenarioPath; }
    public void setScenarioPath(String scenarioPath) { this.scenarioPath = scenarioPath; }
    public String getDefenseFile() { return defenseFile; }
    public void setDefenseFile(String defenseFile) { this.defenseFile = defenseFile; }
    public String getTechniqueIds() { return techniqueIds; }
    public void setTechniqueIds(String techniqueIds) { this.techniqueIds = techniqueIds; }
    public String getTacticNames() { return tacticNames; }
    public void setTacticNames(String tacticNames) { this.tacticNames = tacticNames; }
    public Date getCreatedAt() { return createdAt; }
    public void setCreatedAt(Date createdAt) { this.createdAt = createdAt; }
}
