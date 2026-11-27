# Technical Assessment — Technical Limitations & Production Roadmap

**Assessment Context:** Explicit documentation of technical trade-offs, architecture boundaries, and production roadmap recommendations for PhishShield AI.

---

## 1. Architecture Boundaries & Technical Trade-Offs

### 1.1 In-Memory Rate Limiting
- **Current State:** Rate limiting is managed via `Flask-Limiter` with default in-memory storage (`memory://`).
- **Limitation:** In a multi-worker production environment (e.g., Gunicorn with 4 workers), each worker maintains an isolated in-memory limit counter. A client can bypass the rate limit by distributing requests across worker processes.
- **Production Roadmap:** Transition `Flask-Limiter` to a distributed Redis backend (`storage_uri="redis://redis:6379/0"`).

### 1.2 SQLite Concurrency & Database Locking
- **Current State:** Persistence relies on SQLite (`phishshield.db`).
- **Limitation:** SQLite uses database-level locking during write operations. Under concurrent write spikes (such as automated bulk scans and rapid extension telemetry), SQLite will throw `sqlite3.OperationalError: database is locked`.
- **Production Roadmap:** Replace SQLite with PostgreSQL or MySQL via SQLAlchemy connection pooling (`pool_size=10, max_overflow=20`).

### 1.3 Random Forest Classifier File Size (803 MB)
- **Current State:** `url_model.pkl` is an 803.4 MB unpruned Random Forest.
- **Limitation:** Large artifact size increases Docker container image bloat, increases deployment cold-start latency, and requires substantial RAM (~1.2 GB per worker).
- **Production Roadmap:**
  1. Prune tree depth and max leaf nodes (`max_depth=15, min_samples_leaf=5`) during retraining.
  2. Export the pipeline to **ONNX format** with INT8 quantization, reducing model size by up to 80% and accelerating inference.

### 1.4 Browser Extension Permission Scope
- **Current State:** The extension requests host permissions for `<all_urls>`.
- **Limitation:** Chrome Web Store security reviews scrutinize broad `<all_urls>` host permissions and require extensive privacy policy disclosures.
- **Production Roadmap:** Leverage Chrome's `activeTab` permission model to scan only user-activated pages, reserving passive background scanning for whitelisted high-risk tab navigations.
