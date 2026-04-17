# PyInstaller spec file — builds PyShark into a standalone .exe
block_cipher = None

a = Analysis(
    ['src/network_analyzer.py'],
    pathex=['.'],
    binaries=[],
    datas=[],
    hiddenimports=[
        'scapy.all',
        'scapy.layers.inet',
        'scapy.layers.inet6',
        'scapy.layers.l2',
        'scapy.layers.dns',
        'scapy.layers.dhcp',
        'scapy.sendrecv',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='PyShark',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,        # No console window
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
