// APT 组织中文名映射(详情页/列表页共用)
const GROUP_NAMES = {
  'dragonfly-energetic-bear': '蜻蜓 · 能量熊',
  'apt23': '毒藤 APT23',
  'apt23-tropic-trooper': '毒藤 / 热带骑兵 APT23',
  'darkhotel': '暗黑客栈 DarkHotel',
  'muddywater': '污水 MuddyWater',
  'muddywater-dev': '污水 / DEV-1084',
  'apt-c-01': '毒云藤 APT-C-01',
  'greenspot': '绿斑 GreenSpot',
  'apt29': '舒适熊 APT29',
  'apt29-not-so-cozy': '舒适熊 APT29',
  'transparenttribe': '透明部落 TransparentTribe',
  'apt36': '透明部落 APT36',
  'apt27': '熊猫信使 APT27',
  'apt27-e617': '铁虎 / 幸运鼠 DRBControl',
  'apt28': '花式熊 APT28',
  'sidewinder': '响尾蛇 SideWinder',
  'lazarus': '拉撒路 Lazarus',
  'lazarus-defense-supply-chain': '拉撒路 Lazarus',
  'bitter': '蔓灵花 Bitter',
  'bitter-apt-q-37': '蔓灵花 APT-Q-37',
  'apt-q-37': '蔓灵花 APT-Q-37',
  'apt-q-37-apt-q-41-apt-q-39': '蔓灵花等多组织',
  'apt15': 'APT15',
  'donot': '肚脑虫 Donot',
  'donot-apt-q-38': '肚脑虫 APT-Q-38',
  'apt-q-38': '肚脑虫 APT-Q-38',
  'apt-q-38-donot': '肚脑虫 APT-Q-38',
  'crashoverride': 'CrashOverride / Industroyer2',
  'bluenoroff-stardust-chollima': '蓝诺夫 · 星尘 Chollima',
  'bluenoroff': '蓝诺夫 BlueNoroff',
  'bluenoroff-lazarus': '蓝诺夫 BlueNoroff',
  'spyder': '摩诃草 Spyder',
  'spyder-xxxxxxxxxxxx': '摩诃草 Spyder',
  'patchwork': '摩诃草 Patchwork',
  'apt-q-36': '摩诃草 APT-Q-36',
  'apt-q-36-patchwork': '摩诃草 APT-Q-36',
  'apt-q-12': '伪猎者 APT-Q-12',
  'apt-q-14': '旺刺 APT-Q-14',
  'apt-c-48': 'APT-C-48(CNC)',
  'apt-c-48-cnc-v1': 'APT-C-48(CNC)',
  'apt-c-48-cnc-v2': 'APT-C-48(CNC)',
  'apt-c-44-purplefox-2fe8': '紫狐 PurpleFox',
  'aoqin-dragon': '傲钦龙 Aoqin Dragon',
  'apt10': '石熊猫 APT10',
  'apt10-apt10': '石熊猫 APT10',
  'chimera': '奇美拉 Chimera',
  'desert-falcons': '沙漠之隼 Desert Falcons',
  'earth-yako': 'Earth Yako',
  'earth-yako-yako': 'Earth Yako',
  'molerats': '加沙黑帮 MoleRATs',
  'oceanlotus': '海莲花 OceanLotus',
  'uat4356': 'UAT4356(伊朗)',
  'unknown-zaardoor': '未知组织 Zardoor',
  'chinese-state-sponsored': '国家级威胁组织'
}

export function groupZh(code) {
  if (!code) return ''
  if (GROUP_NAMES[code]) return GROUP_NAMES[code]
  // 去掉尾部哈希后缀再试一次,如 apt27-7306 -> apt27
  const stripped = code.replace(/-[0-9a-f]{4,}$/i, '')
  if (GROUP_NAMES[stripped]) return GROUP_NAMES[stripped]
  return code
}
