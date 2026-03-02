from pydantic import BaseModel

class ActivityLog(BaseModel):
    user_id: str
    action: str
    resource: str
    records_accessed: int
    ip_address: str | None = None
