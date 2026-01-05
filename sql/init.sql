CREATE SCHEMA IF NOT EXISTS core;
CREATE SCHEMA IF NOT EXISTS audit;

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";


CREATE TABLE core.users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'doctor',
    full_name VARCHAR(100),
    email VARCHAR(100),
    specialty VARCHAR(50),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);


CREATE TABLE IF NOT EXISTS core.patients (
    id SERIAL PRIMARY KEY,
    patient_code VARCHAR(20) UNIQUE NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    date_of_birth DATE,
    gender VARCHAR(10),
    doctor_id INTEGER REFERENCES core.users(id) ON DELETE SET NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS core.devices (
    id SERIAL PRIMARY KEY,
    device_id VARCHAR(100) UNIQUE NOT NULL,
    secret_hash VARCHAR(255),
    public_key TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    registered_by INTEGER REFERENCES core.users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP WITH TIME ZONE
);

CREATE TABLE IF NOT EXISTS core.readings (
    id SERIAL PRIMARY KEY,
    device_id VARCHAR(100) NOT NULL,
    patient_id INTEGER REFERENCES core.patients(id),
    spo2 DECIMAL(5,2) NOT NULL CHECK (spo2 >= 0 AND spo2 <= 100),
    bpm INTEGER NOT NULL CHECK (bpm >= 0 AND bpm <= 300),
    reading_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    signature VARCHAR(255),
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);


CREATE TABLE IF NOT EXISTS audit.audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES core.users(id),
    device_id VARCHAR(100),
    action VARCHAR(100) NOT NULL,
    status VARCHAR(50) NOT NULL,
    details TEXT,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    record_hash VARCHAR(64)
);


CREATE OR REPLACE FUNCTION audit.calculate_audit_hash()
RETURNS TRIGGER AS $$
BEGIN
    NEW.record_hash := encode(
        sha256(
            CONCAT(
                COALESCE(NEW.user_id::TEXT, ''),
                COALESCE(NEW.device_id, ''),
                NEW.action,
                NEW.status,
                COALESCE(NEW.details, ''),
                COALESCE(NEW.ip_address::TEXT, ''),
                COALESCE(NEW.user_agent, ''),
                COALESCE(NEW.created_at::TEXT, CURRENT_TIMESTAMP::TEXT)
            )::bytea
        ),
        'hex'
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE TRIGGER set_audit_hash
    BEFORE INSERT OR UPDATE ON audit.audit_logs
    FOR EACH ROW
    EXECUTE FUNCTION audit.calculate_audit_hash();

CREATE OR REPLACE FUNCTION audit.verify_log_integrity(log_id INTEGER)
RETURNS TABLE (
    is_valid BOOLEAN,
    current_hash TEXT,
    calculated_hash TEXT,
    log_details JSON
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        al.record_hash = encode(
            sha256(
                CONCAT(
                    COALESCE(al.user_id::TEXT, ''),
                    COALESCE(al.device_id, ''),
                    al.action,
                    al.status,
                    COALESCE(al.details, ''),
                    COALESCE(al.ip_address::TEXT, ''),
                    COALESCE(al.user_agent, ''),
                    al.created_at::TEXT
                )::bytea
            ),
            'hex'
        ) AS is_valid,
        al.record_hash AS current_hash,
        encode(
            sha256(
                CONCAT(
                    COALESCE(al.user_id::TEXT, ''),
                    COALESCE(al.device_id, ''),
                    al.action,
                    al.status,
                    COALESCE(al.details, ''),
                    COALESCE(al.ip_address::TEXT, ''),
                    COALESCE(al.user_agent, ''),
                    al.created_at::TEXT
                )::bytea
            ),
            'hex'
        ) AS calculated_hash,
        json_build_object(
            'id', al.id,
            'action', al.action,
            'status', al.status,
            'created_at', al.created_at
        ) AS log_details
    FROM audit.audit_logs al
    WHERE al.id = log_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER update_users_updated_at
    BEFORE UPDATE ON core.users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE OR REPLACE TRIGGER update_patients_updated_at
    BEFORE UPDATE ON core.patients
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();


INSERT INTO core.users (username, password_hash, role, full_name, specialty, is_active) VALUES
('dr.jose', '$2b$12$vF2pm2krgOYK70n5mPI8ueK6PPg3FgEfw03zq9.kPHYctEMeAOwCS', 'doctor', 'Dr. Jose Silva', 'General Practitioner', TRUE),
('dr.ana', '$2b$12$jdmPdC7QVQfWjFrAP2b4cOk7NCqZpx3fjUfd31lPppwV8N5NbMwJC', 'doctor', 'Dr. Ana Costa', 'Cardiology', TRUE),
('igor', '$2b$12$6lpHDXf2bjJ8wd9677HmQeC.U1epUjfSUYzLGIpjVKLr8puMm9Rla', 'doctor', 'Dr. Igor', 'General doctor', TRUE),
('admin', '$2b$12$li8YoM2fuTX3pujW4Vmj6OUZERM8cx8zFC8VFk/iaRAPuEprOunma', 'admin', 'System Administrator', 'IT', TRUE)
ON CONFLICT (username) DO NOTHING;


INSERT INTO core.patients (patient_code, full_name, date_of_birth, gender, doctor_id) VALUES
('PAT-001', 'Maria Santos', '1950-05-15', 'F', 1),
('PAT-002', 'João Oliveira', '1965-08-22', 'M', 1),
('PAT-003', 'Ana Costa', '1942-03-10', 'F', 2),
('PAT-004', 'Carlos Mendes', '1978-11-30', 'M', 2)
ON CONFLICT (patient_code) DO NOTHING;

INSERT INTO core.devices (device_id, secret_hash, is_active, registered_by) VALUES
('OXIM-001', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', TRUE, 1),
('OXIM-002', 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce', TRUE, 2)
ON CONFLICT (device_id) DO NOTHING;

INSERT INTO core.readings (device_id, patient_id, spo2, bpm, reading_timestamp, signature) VALUES
('OXIM-001', 1, 98.5, 75, '2024-01-15 10:30:00+00', 'sample_signature_1'),
('OXIM-001', 1, 97.2, 72, '2024-01-15 11:30:00+00', 'sample_signature_2'),
('OXIM-002', 3, 99.0, 68, '2024-01-15 12:00:00+00', 'sample_signature_3')
ON CONFLICT DO NOTHING;

INSERT INTO audit.audit_logs (user_id, action, status, details) VALUES
(1, 'SYSTEM_INIT', 'SUCCESS', 'Database initialized with sample data'),
(3, 'USER_LOGIN', 'SUCCESS', 'Admin user logged in')
ON CONFLICT DO NOTHING;


CREATE INDEX IF NOT EXISTS idx_users_username ON core.users(username);
CREATE INDEX IF NOT EXISTS idx_users_role ON core.users(role);

CREATE INDEX IF NOT EXISTS idx_patients_patient_code ON core.patients(patient_code);
CREATE INDEX IF NOT EXISTS idx_patients_doctor_id ON core.patients(doctor_id);

CREATE INDEX IF NOT EXISTS idx_devices_device_id ON core.devices(device_id);
CREATE INDEX IF NOT EXISTS idx_devices_is_active ON core.devices(is_active);

CREATE INDEX IF NOT EXISTS idx_readings_patient_id ON core.readings(patient_id);
CREATE INDEX IF NOT EXISTS idx_readings_device_id ON core.readings(device_id);
CREATE INDEX IF NOT EXISTS idx_readings_timestamp ON core.readings(reading_timestamp);
CREATE INDEX IF NOT EXISTS idx_readings_created_at ON core.readings(created_at);

CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit.audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_device_id ON audit.audit_logs(device_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit.audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit.audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_record_hash ON audit.audit_logs(record_hash);


REVOKE ALL ON SCHEMA core FROM PUBLIC;
REVOKE ALL ON SCHEMA audit FROM PUBLIC;

GRANT USAGE ON SCHEMA core TO tcc_user;
GRANT USAGE ON SCHEMA audit TO tcc_user;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA core TO tcc_user;
GRANT SELECT, INSERT ON audit.audit_logs TO tcc_user;

GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA core TO tcc_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA audit TO tcc_user;

GRANT EXECUTE ON FUNCTION audit.verify_log_integrity(INTEGER) TO tcc_user;


CREATE OR REPLACE VIEW core.doctor_dashboard AS
SELECT
    u.id as doctor_id,
    u.full_name as doctor_name,
    COUNT(DISTINCT p.id) as patient_count,
    COUNT(r.id) as total_readings,
    MAX(r.reading_timestamp) as latest_reading,
    AVG(r.spo2) as avg_spo2,
    AVG(r.bpm) as avg_bpm
FROM core.users u
LEFT JOIN core.patients p ON p.doctor_id = u.id
LEFT JOIN core.readings r ON r.patient_id = p.id
WHERE u.role = 'doctor'
GROUP BY u.id, u.full_name;

CREATE OR REPLACE VIEW core.patient_stats AS
SELECT
    p.patient_code,
    p.full_name,
    COUNT(r.id) as reading_count,
    MIN(r.spo2) as min_spo2,
    MAX(r.spo2) as max_spo2,
    AVG(r.spo2) as avg_spo2,
    MIN(r.bpm) as min_bpm,
    MAX(r.bpm) as max_bpm,
    AVG(r.bpm) as avg_bpm,
    MAX(r.reading_timestamp) as last_reading
FROM core.patients p
LEFT JOIN core.readings r ON r.patient_id = p.id
GROUP BY p.id, p.patient_code, p.full_name;

GRANT SELECT ON core.doctor_dashboard TO tcc_user;
GRANT SELECT ON core.patient_stats TO tcc_user;

DO $$
BEGIN
    RAISE NOTICE 'Database initialized successfully!';
    RAISE NOTICE 'Schemas created: core, audit';
    RAISE NOTICE 'Default users created: dr.jose (doctor), dr.ana (doctor), admin (admin)';
    RAISE NOTICE 'Password for all users: "secret1234"';
    RAISE NOTICE 'Sample patients: PAT-001 to PAT-004';
    RAISE NOTICE 'Sample devices: OXIM-001, OXIM-002';
END $$;