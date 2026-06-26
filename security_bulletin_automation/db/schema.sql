-- ============================================================
-- CARONTE / ARGOS — Schema Oracle 21c
-- Ejecutar como usuario DBA o con privilegios CREATE TABLE.
-- El schema objetivo se pasa al conectar (variable ORACLE_SCHEMA).
-- ============================================================

-- ── Usuarios ─────────────────────────────────────────────────
CREATE TABLE caronte_users (
    username        VARCHAR2(100)  NOT NULL,
    password_hash   VARCHAR2(255)  NOT NULL,
    totp_secret     VARCHAR2(100),
    role            VARCHAR2(20)   DEFAULT 'user' NOT NULL,
    created_at      TIMESTAMP      DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_users PRIMARY KEY (username),
    CONSTRAINT ck_users_role CHECK (role IN ('admin', 'user'))
);

-- ── Amenazas ──────────────────────────────────────────────────
CREATE TABLE caronte_threats (
    threat_id               VARCHAR2(30)   NOT NULL,
    fecha_deteccion         VARCHAR2(20),
    fuente                  VARCHAR2(200),
    tipo_va                 VARCHAR2(50),
    cves_identificados      VARCHAR2(1000),
    nombre                  VARCHAR2(500),
    descripcion_tecnica     CLOB,
    descripcion_riesgo      CLOB,
    ttps                    VARCHAR2(1000),
    probabilidad            VARCHAR2(50),
    impacto                 VARCHAR2(500),
    criticidad              VARCHAR2(50),
    accion_recomendada      CLOB,
    area_responsable        VARCHAR2(200),
    fecha_escalamiento      VARCHAR2(20),
    afecta_activos          VARCHAR2(200),
    comentarios_tenable     CLOB,
    bloqueo_antivirus       VARCHAR2(100),
    bloqueo_firewall        VARCHAR2(100),
    caso_firewall           VARCHAR2(100),
    created_at              TIMESTAMP      DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_threats PRIMARY KEY (threat_id)
);

-- ── IoCs ──────────────────────────────────────────────────────
CREATE TABLE caronte_iocs (
    ioc_id              NUMBER         GENERATED ALWAYS AS IDENTITY,
    threat_id           VARCHAR2(30)   NOT NULL,
    tipo_ioc            VARCHAR2(50),
    indicador           VARCHAR2(2000),
    bloqueo_antivirus   VARCHAR2(100),
    bloqueo_firewall    VARCHAR2(100),
    created_at          TIMESTAMP      DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_iocs    PRIMARY KEY (ioc_id),
    CONSTRAINT fk_ioc_th  FOREIGN KEY (threat_id)
        REFERENCES caronte_threats(threat_id) ON DELETE CASCADE
);

-- ── Índices de búsqueda ──────────────────────────────────────
CREATE INDEX idx_threats_fuente    ON caronte_threats(fuente);
CREATE INDEX idx_threats_fecha     ON caronte_threats(fecha_deteccion);
CREATE INDEX idx_threats_critico   ON caronte_threats(criticidad);
CREATE INDEX idx_iocs_threat       ON caronte_iocs(threat_id);
CREATE INDEX idx_iocs_tipo         ON caronte_iocs(tipo_ioc);
