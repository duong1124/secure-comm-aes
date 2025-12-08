import yaml
from pathlib import Path
from dataclasses import dataclass
from typing import Tuple


@dataclass
class CryptoConfig:
    key: bytes
    iv_cbc: bytes
    iv_gcm: bytes
    aad: bytes
    tag_length: int
    block_size: int


@dataclass
class MITMConfig:
    avoid_last_blocks_ecb: int
    avoid_last_blocks_cbc: int
    avoid_last_blocks_gcm: int
    tamper_start_ratio: float
    tamper_end_ratio: float
    xor_mask: int


@dataclass
class VisualizationConfig:
    figure_size_comparison: Tuple[int, int]
    figure_size_blocked: Tuple[int, int]
    histogram_bins: int
    histogram_range: Tuple[int, int]


@dataclass
class Config:
    image_path: str
    crypto: CryptoConfig
    mitm: MITMConfig
    visualization: VisualizationConfig


def load_config(config_path: str = "config.yaml") -> Config:
    config_file = Path(config_path)

    if not config_file.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with open(config_file, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)

    # Parse crypto config
    crypto_data = data['crypto']
    crypto = CryptoConfig(
        key=crypto_data['key'].encode('utf-8'),
        iv_cbc=crypto_data['iv_cbc'].encode('utf-8'),
        iv_gcm=crypto_data['iv_gcm'].encode('utf-8'),
        aad=crypto_data['aad'].encode('utf-8'),
        tag_length=crypto_data['tag_length'],
        block_size=crypto_data['block_size']
    )

    # Parse MITM config
    mitm_data = data['mitm']
    mitm = MITMConfig(
        avoid_last_blocks_ecb=mitm_data['avoid_last_blocks_ecb'],
        avoid_last_blocks_cbc=mitm_data['avoid_last_blocks_cbc'],
        avoid_last_blocks_gcm=mitm_data['avoid_last_blocks_gcm'],
        tamper_start_ratio=mitm_data['tamper_start_ratio'],
        tamper_end_ratio=mitm_data['tamper_end_ratio'],
        xor_mask=mitm_data['xor_mask']
    )

    # Parse visualization config
    vis_data = data['visualization']
    visualization = VisualizationConfig(
        figure_size_comparison=tuple(vis_data['figure_size_comparison']),
        figure_size_blocked=tuple(vis_data['figure_size_blocked']),
        histogram_bins=vis_data['histogram_bins'],
        histogram_range=tuple(vis_data['histogram_range'])
    )

    return Config(
        image_path=data['paths']['image_path'],
        crypto=crypto,
        mitm=mitm,
        visualization=visualization
    )