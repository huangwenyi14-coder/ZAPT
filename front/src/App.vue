<template>
  <div id="app">
    <router-view/>
  </div>
</template>

<script>
export default {
  name: 'App'
}
</script>

<style>
/* ============================================================
   全局主题:浅色科技风(对齐参考站最终生效的 Light technology theme)
   ============================================================ */
:root {
  --page: #eef6ff;
  --panel: #ffffff;
  --panel-soft: #f6faff;
  --ink: #10243b;
  --muted: #50657c;
  --faint: #71859a;
  --line: rgba(50, 91, 135, .22);
  --line-soft: rgba(69, 111, 153, .15);
  --navy: #143252;
  --blue: #226ee8;
  --cyan: #0694b4;
  --teal: #0b9b83;
  --green: #15965f;
  --red: #df3f55;
  --amber: #bf7817;
  --shadow: 0 14px 34px rgba(40, 83, 130, .14);
}

html {
  min-height: 100%;
  color-scheme: light;
}

body {
  margin: 0;
  min-height: 100vh;
  color: var(--ink);
  font-family: "Microsoft YaHei", "Segoe UI", system-ui, -apple-system, sans-serif;
  font-size: 13px;
  background:
    radial-gradient(circle at 17% -7%, rgba(79, 140, 255, .18), transparent 28%),
    radial-gradient(circle at 88% 0%, rgba(6, 148, 180, .14), transparent 25%),
    linear-gradient(rgba(50, 91, 135, .06) 1px, transparent 1px),
    linear-gradient(90deg, rgba(50, 91, 135, .055) 1px, transparent 1px),
    linear-gradient(180deg, #f7fbff 0%, #eef6ff 48%, #f6fbff 100%);
  background-size: auto, auto, 32px 32px, 32px 32px, auto;
  background-attachment: fixed;
}

a {
  color: var(--blue);
}

/* 头像统一裁切规则:填满容器、竖版人像优先显示上半部分(脸部) */
.el-avatar > img {
  width: 100%;
  height: 100%;
  object-fit: cover;
  object-position: top;
}

/* ---------- 面板 / 按钮 / 标签(参考站通用组件类) ---------- */
.cc-panel {
  border: 1px solid var(--line-soft);
  border-radius: 8px;
  background: var(--panel);
  box-shadow: var(--shadow);
  overflow: hidden;
}

.cc-primary-button,
.cc-outline-button,
.cc-text-button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  border-radius: 6px;
  padding: 8px 15px;
  font-size: 13px;
  font-weight: 700;
  cursor: pointer;
  text-decoration: none;
  transition: filter .2s ease, border-color .2s ease;
  border: 1px solid transparent;
}

.cc-primary-button {
  color: #ffffff;
  border-color: rgba(34, 110, 232, .42);
  background: linear-gradient(135deg, #226ee8, #16a8c9);
}

.cc-primary-button:hover {
  filter: brightness(1.06);
}

.cc-outline-button,
.cc-text-button {
  color: var(--navy);
  border-color: rgba(34, 110, 232, .24);
  background: #ffffff;
}

.cc-outline-button:hover,
.cc-text-button:hover {
  border-color: rgba(34, 110, 232, .45);
  color: var(--blue);
}

.cc-tag-row {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.cc-tag-row span {
  padding: 3px 10px;
  border-radius: 999px;
  border: 1px solid rgba(34, 110, 232, .2);
  background: rgba(34, 110, 232, .06);
  color: #2f5f96;
  font-size: 11px;
  font-weight: 600;
}

/* ---------- 页面 Hero ---------- */
.page-hero {
  padding: 22px 24px 18px;
  border: 1px solid var(--line-soft);
  border-radius: 8px;
  background:
    radial-gradient(circle at 92% 8%, rgba(6, 148, 180, .1), transparent 40%),
    #ffffff;
  box-shadow: var(--shadow);
}

.hero-kicker {
  display: inline-flex;
  align-items: center;
  padding: 4px 12px;
  border-radius: 999px;
  border: 1px solid rgba(34, 110, 232, .24);
  background: rgba(34, 110, 232, .07);
  color: var(--blue);
  font-size: 11px;
  font-weight: 800;
  letter-spacing: .08em;
  margin-bottom: 10px;
}

.hero-kicker.amber {
  border-color: rgba(191, 120, 23, .3);
  background: rgba(255, 189, 90, .12);
  color: var(--amber);
}

.page-hero h1 {
  margin: 0 0 8px;
  color: var(--navy);
  font-size: 22px;
  font-weight: 850;
}

.page-hero .hero-desc {
  margin: 0 0 14px;
  color: var(--muted);
  font-size: 13px;
  line-height: 1.7;
  max-width: 900px;
}

.hero-stat-row {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
}

.hero-stat-row .hero-stat {
  display: flex;
  align-items: baseline;
  gap: 7px;
  padding: 7px 13px;
  border-radius: 8px;
  border: 1px solid var(--line-soft);
  background: var(--panel-soft);
}

.hero-stat-row .hero-stat b {
  color: var(--navy);
  font-size: 18px;
  font-weight: 850;
}

.hero-stat-row .hero-stat span {
  color: var(--muted);
  font-size: 11.5px;
}

/* ---------- 区块标题行 ---------- */
.cc-section-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  min-height: 46px;
  padding: 10px 16px;
  border-bottom: 1px solid var(--line-soft);
  background: var(--panel-soft);
}

.cc-section-head h1,
.cc-section-head h2 {
  margin: 0;
  color: var(--navy);
  font-size: 16px;
  font-weight: 800;
}

.cc-section-kicker {
  display: block;
  color: var(--cyan);
  font-size: 10.5px;
  font-weight: 800;
  letter-spacing: .06em;
}

/* ---------- 滚动条 ---------- */
::-webkit-scrollbar {
  width: 9px;
  height: 9px;
}

::-webkit-scrollbar-thumb {
  background: rgba(50, 91, 135, .22);
  border-radius: 6px;
}

::-webkit-scrollbar-track {
  background: transparent;
}
</style>
