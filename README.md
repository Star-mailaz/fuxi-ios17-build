# fuxi / iOS 17.7 21H16 —— 复现构建（MIT 式：源码来自 Kerfand，二进制自己生成）

目标：用 GitHub Actions（Ubuntu）复现 Kerfand 的 arm64e iOS 17 构建链，最终产出可 `fastboot boot` 的镜像。

## 阶段

1. **bootstrap**（当前）：环境 + patch 链 + UniXNU 配置解析
2. kernel：下载 21H16 IPSW，编译 arm64e 内核
3. probe：`pack-ios17-hidpath.py` 的 `UFS_PROBE=10` 只读探针镜像
4. root：生成 userdata-root.img 并刷写（不可逆，最后一步）

## 来源

- 源码/补丁：`Kerfand/UniXNU-Fuxi-Arm64e-iOS17`
- 框架基线：`SadNutWall/UniXNU`（fuxi 分支）
- 苹果输入：iPhone15,2 (D73AP) iOS 17.7 21H16 IPSW，自行从 Apple 下载

## 注意

- 本仓库不含任何苹果二进制或构建产物。
- 所有脚本里的作者本机路径（`/home/xiaomi`、`/mnt/f`）都需要替换。
