package com.github.guoyyit.domaintyposquatdetectionjava.model;

/**
 * 仿冒特征类型。枚举顺序即判定结果中命中特征的稳定排序顺序。
 */
public enum FeatureType {
    EDIT_DISTANCE,
    INSERT_DELETE,
    HOMOGLYPH,
    TLD_SWAP,
    BRAND_AFFIX,
    SUBDOMAIN_DISGUISE
}
