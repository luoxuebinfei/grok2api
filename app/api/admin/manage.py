"""管理接口 - Token管理和系统配置"""

import secrets
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from pathlib import Path
from fastapi import APIRouter, HTTPException, Depends, Header
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from app.core.config import setting
from app.core.logger import logger
from app.services.grok.token import token_manager
from app.models.grok_models import TokenType


router = APIRouter(tags=["管理"])

# 常量
STATIC_DIR = Path(__file__).parents[2] / "template"
TEMP_DIR = Path(__file__).parents[3] / "data" / "temp"
IMAGE_CACHE_DIR = TEMP_DIR / "image"
VIDEO_CACHE_DIR = TEMP_DIR / "video"
SESSION_EXPIRE_HOURS = 24
BYTES_PER_KB = 1024
BYTES_PER_MB = 1024 * 1024

# 会话存储
_sessions: Dict[str, datetime] = {}


# === 请求/响应模型 ===

class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    success: bool
    token: Optional[str] = None
    message: str


class AddTokensRequest(BaseModel):
    tokens: List[str]
    token_type: str


class DeleteTokensRequest(BaseModel):
    tokens: List[str]
    token_type: str


class TokenInfo(BaseModel):
    token: str
    token_type: str
    created_time: Optional[int] = None
    remaining_queries: int
    heavy_remaining_queries: int
    status: str
    tags: List[str] = []
    note: str = ""


class TokenListResponse(BaseModel):
    success: bool
    data: List[TokenInfo]
    total: int


class UpdateSettingsRequest(BaseModel):
    global_config: Optional[Dict[str, Any]] = None
    grok_config: Optional[Dict[str, Any]] = None


class UpdateTokenTagsRequest(BaseModel):
    token: str
    token_type: str
    tags: List[str]


class UpdateTokenNoteRequest(BaseModel):
    token: str
    token_type: str
    note: str


class TestTokenRequest(BaseModel):
    token: str
    token_type: str


class BatchTestTokensRequest(BaseModel):
    """批量测试Token请求"""
    mode: str = "selected"  # selected: 测试选中, all: 测试全部, filter: 按条件筛选
    tokens: Optional[List[Dict[str, str]]] = None  # mode=selected 时使用
    token_type: Optional[str] = None  # mode=filter 时筛选类型
    status: Optional[str] = None  # mode=filter 时筛选状态
    concurrency: int = 3  # 并发数


# === 辅助函数 ===

def validate_token_type(token_type_str: str) -> TokenType:
    """验证Token类型"""
    if token_type_str not in ["sso", "ssoSuper"]:
        raise HTTPException(
            status_code=400,
            detail={"error": "无效的Token类型", "code": "INVALID_TYPE"}
        )
    return TokenType.NORMAL if token_type_str == "sso" else TokenType.SUPER


def parse_created_time(created_time) -> Optional[int]:
    """解析创建时间"""
    if isinstance(created_time, str):
        return int(created_time) if created_time else None
    elif isinstance(created_time, int):
        return created_time
    return None


def calculate_token_stats(tokens: Dict[str, Any], token_type: str) -> Dict[str, int]:
    """计算Token统计"""
    total = len(tokens)
    expired = sum(1 for t in tokens.values() if t.get("status") == "expired")

    if token_type == "normal":
        unused = sum(1 for t in tokens.values()
                    if t.get("status") != "expired" and t.get("remainingQueries", -1) == -1)
        limited = sum(1 for t in tokens.values()
                     if t.get("status") != "expired" and t.get("remainingQueries", -1) == 0)
        active = sum(1 for t in tokens.values()
                    if t.get("status") != "expired" and t.get("remainingQueries", -1) > 0)
    else:
        unused = sum(1 for t in tokens.values()
                    if t.get("status") != "expired" and
                    t.get("remainingQueries", -1) == -1 and t.get("heavyremainingQueries", -1) == -1)
        limited = sum(1 for t in tokens.values()
                     if t.get("status") != "expired" and
                     (t.get("remainingQueries", -1) == 0 or t.get("heavyremainingQueries", -1) == 0))
        active = sum(1 for t in tokens.values()
                    if t.get("status") != "expired" and
                    (t.get("remainingQueries", -1) > 0 or t.get("heavyremainingQueries", -1) > 0))

    return {"total": total, "unused": unused, "limited": limited, "expired": expired, "active": active}


def verify_admin_session(authorization: Optional[str] = Header(None)) -> bool:
    """验证管理员会话"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail={"error": "未授权访问", "code": "UNAUTHORIZED"})
    
    token = authorization[7:]
    
    if token not in _sessions:
        raise HTTPException(status_code=401, detail={"error": "会话无效", "code": "SESSION_INVALID"})
    
    if datetime.now() > _sessions[token]:
        del _sessions[token]
        raise HTTPException(status_code=401, detail={"error": "会话已过期", "code": "SESSION_EXPIRED"})
    
    return True


def get_token_status(token_data: Dict[str, Any], token_type: str) -> str:
    """获取Token状态"""
    if token_data.get("status") == "expired":
        return "失效"
    
    remaining = token_data.get("remainingQueries", -1)
    heavy_remaining = token_data.get("heavyremainingQueries", -1)
    
    relevant = max(remaining, heavy_remaining) if token_type == "ssoSuper" else remaining
    
    if relevant == -1:
        return "未使用"
    elif relevant == 0:
        return "限流中"
    else:
        return "正常"


def _calculate_dir_size(directory: Path) -> int:
    """计算目录大小"""
    total = 0
    for file_path in directory.iterdir():
        if file_path.is_file():
            try:
                total += file_path.stat().st_size
            except Exception as e:
                logger.warning(f"[Admin] 无法获取文件大小: {file_path.name}, {e}")
    return total


def _format_size(size_bytes: int) -> str:
    """格式化文件大小"""
    size_mb = size_bytes / BYTES_PER_MB
    if size_mb < 1:
        return f"{size_bytes / BYTES_PER_KB:.1f} KB"
    return f"{size_mb:.1f} MB"


# === 页面路由 ===

@router.get("/login", response_class=HTMLResponse)
async def login_page():
    """登录页面"""
    login_html = STATIC_DIR / "login.html"
    if login_html.exists():
        return login_html.read_text(encoding="utf-8")
    raise HTTPException(status_code=404, detail="登录页面不存在")


@router.get("/manage", response_class=HTMLResponse)
async def manage_page():
    """管理页面"""
    admin_html = STATIC_DIR / "admin.html"
    if admin_html.exists():
        return admin_html.read_text(encoding="utf-8")
    raise HTTPException(status_code=404, detail="管理页面不存在")


# === API端点 ===

@router.post("/api/login", response_model=LoginResponse)
async def admin_login(request: LoginRequest) -> LoginResponse:
    """管理员登录"""
    try:
        logger.debug(f"[Admin] 登录尝试: {request.username}")

        expected_user = setting.global_config.get("admin_username", "")
        expected_pass = setting.global_config.get("admin_password", "")

        if request.username != expected_user or request.password != expected_pass:
            logger.warning(f"[Admin] 登录失败: {request.username}")
            return LoginResponse(success=False, message="用户名或密码错误")

        session_token = secrets.token_urlsafe(32)
        _sessions[session_token] = datetime.now() + timedelta(hours=SESSION_EXPIRE_HOURS)

        logger.debug(f"[Admin] 登录成功: {request.username}")
        return LoginResponse(success=True, token=session_token, message="登录成功")

    except Exception as e:
        logger.error(f"[Admin] 登录异常: {e}")
        raise HTTPException(status_code=500, detail={"error": f"登录失败: {e}", "code": "LOGIN_ERROR"})


@router.post("/api/logout")
async def admin_logout(_: bool = Depends(verify_admin_session), authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    """管理员登出"""
    try:
        if authorization and authorization.startswith("Bearer "):
            token = authorization[7:]
            if token in _sessions:
                del _sessions[token]
                logger.debug("[Admin] 登出成功")
                return {"success": True, "message": "登出成功"}

        logger.warning("[Admin] 登出失败: 无效会话")
        return {"success": False, "message": "无效的会话"}

    except Exception as e:
        logger.error(f"[Admin] 登出异常: {e}")
        raise HTTPException(status_code=500, detail={"error": f"登出失败: {e}", "code": "LOGOUT_ERROR"})


@router.get("/api/tokens", response_model=TokenListResponse)
async def list_tokens(_: bool = Depends(verify_admin_session)) -> TokenListResponse:
    """获取Token列表"""
    try:
        logger.debug("[Admin] 获取Token列表")

        all_tokens = token_manager.get_tokens()
        token_list: List[TokenInfo] = []

        # 普通Token
        for token, data in all_tokens.get(TokenType.NORMAL.value, {}).items():
            token_list.append(TokenInfo(
                token=token,
                token_type="sso",
                created_time=parse_created_time(data.get("createdTime")),
                remaining_queries=data.get("remainingQueries", -1),
                heavy_remaining_queries=data.get("heavyremainingQueries", -1),
                status=get_token_status(data, "sso"),
                tags=data.get("tags", []),
                note=data.get("note", "")
            ))

        # Super Token
        for token, data in all_tokens.get(TokenType.SUPER.value, {}).items():
            token_list.append(TokenInfo(
                token=token,
                token_type="ssoSuper",
                created_time=parse_created_time(data.get("createdTime")),
                remaining_queries=data.get("remainingQueries", -1),
                heavy_remaining_queries=data.get("heavyremainingQueries", -1),
                status=get_token_status(data, "ssoSuper"),
                tags=data.get("tags", []),
                note=data.get("note", "")
            ))

        logger.debug(f"[Admin] Token列表获取成功: {len(token_list)}个")
        return TokenListResponse(success=True, data=token_list, total=len(token_list))

    except Exception as e:
        logger.error(f"[Admin] 获取Token列表异常: {e}")
        raise HTTPException(status_code=500, detail={"error": f"获取失败: {e}", "code": "LIST_ERROR"})


@router.post("/api/tokens/add")
async def add_tokens(request: AddTokensRequest, _: bool = Depends(verify_admin_session)) -> Dict[str, Any]:
    """批量添加Token"""
    try:
        logger.debug(f"[Admin] 添加Token: {request.token_type}, {len(request.tokens)}个")

        token_type = validate_token_type(request.token_type)
        await token_manager.add_token(request.tokens, token_type)

        logger.debug(f"[Admin] Token添加成功: {len(request.tokens)}个")
        return {"success": True, "message": f"成功添加 {len(request.tokens)} 个Token", "count": len(request.tokens)}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[Admin] Token添加异常: {e}")
        raise HTTPException(status_code=500, detail={"error": f"添加失败: {e}", "code": "ADD_ERROR"})


@router.post("/api/tokens/delete")
async def delete_tokens(request: DeleteTokensRequest, _: bool = Depends(verify_admin_session)) -> Dict[str, Any]:
    """批量删除Token"""
    try:
        logger.debug(f"[Admin] 删除Token: {request.token_type}, {len(request.tokens)}个")

        token_type = validate_token_type(request.token_type)
        await token_manager.delete_token(request.tokens, token_type)

        logger.debug(f"[Admin] Token删除成功: {len(request.tokens)}个")
        return {"success": True, "message": f"成功删除 {len(request.tokens)} 个Token", "count": len(request.tokens)}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[Admin] Token删除异常: {e}")
        raise HTTPException(status_code=500, detail={"error": f"删除失败: {e}", "code": "DELETE_ERROR"})


@router.get("/api/settings")
async def get_settings(_: bool = Depends(verify_admin_session)) -> Dict[str, Any]:
    """获取配置"""
    try:
        logger.debug("[Admin] 获取配置")
        return {"success": True, "data": {"global": setting.global_config, "grok": setting.grok_config}}
    except Exception as e:
        logger.error(f"[Admin] 获取配置失败: {e}")
        raise HTTPException(status_code=500, detail={"error": f"获取失败: {e}", "code": "GET_SETTINGS_ERROR"})


@router.post("/api/settings")
async def update_settings(request: UpdateSettingsRequest, _: bool = Depends(verify_admin_session)) -> Dict[str, Any]:
    """更新配置"""
    try:
        logger.debug("[Admin] 更新配置")
        await setting.save(global_config=request.global_config, grok_config=request.grok_config)
        logger.debug("[Admin] 配置更新成功")
        return {"success": True, "message": "配置更新成功"}
    except Exception as e:
        logger.error(f"[Admin] 更新配置失败: {e}")
        raise HTTPException(status_code=500, detail={"error": f"更新失败: {e}", "code": "UPDATE_SETTINGS_ERROR"})


@router.get("/api/cache/size")
async def get_cache_size(_: bool = Depends(verify_admin_session)) -> Dict[str, Any]:
    """获取缓存大小"""
    try:
        logger.debug("[Admin] 获取缓存大小")

        image_size = _calculate_dir_size(IMAGE_CACHE_DIR) if IMAGE_CACHE_DIR.exists() else 0
        video_size = _calculate_dir_size(VIDEO_CACHE_DIR) if VIDEO_CACHE_DIR.exists() else 0
        total_size = image_size + video_size

        logger.debug(f"[Admin] 缓存大小: 图片{_format_size(image_size)}, 视频{_format_size(video_size)}")
        
        return {
            "success": True,
            "data": {
                "image_size": _format_size(image_size),
                "video_size": _format_size(video_size),
                "total_size": _format_size(total_size),
                "image_size_bytes": image_size,
                "video_size_bytes": video_size,
                "total_size_bytes": total_size
            }
        }

    except Exception as e:
        logger.error(f"[Admin] 获取缓存大小异常: {e}")
        raise HTTPException(status_code=500, detail={"error": f"获取失败: {e}", "code": "CACHE_SIZE_ERROR"})


@router.post("/api/cache/clear")
async def clear_cache(_: bool = Depends(verify_admin_session)) -> Dict[str, Any]:
    """清理所有缓存"""
    try:
        logger.debug("[Admin] 清理缓存")

        image_count = 0
        video_count = 0

        # 清理图片
        if IMAGE_CACHE_DIR.exists():
            for file_path in IMAGE_CACHE_DIR.iterdir():
                if file_path.is_file():
                    try:
                        file_path.unlink()
                        image_count += 1
                    except Exception as e:
                        logger.error(f"[Admin] 删除失败: {file_path.name}, {e}")

        # 清理视频
        if VIDEO_CACHE_DIR.exists():
            for file_path in VIDEO_CACHE_DIR.iterdir():
                if file_path.is_file():
                    try:
                        file_path.unlink()
                        video_count += 1
                    except Exception as e:
                        logger.error(f"[Admin] 删除失败: {file_path.name}, {e}")

        total = image_count + video_count
        logger.debug(f"[Admin] 缓存清理完成: 图片{image_count}, 视频{video_count}")

        return {
            "success": True,
            "message": f"成功清理缓存，删除图片 {image_count} 个，视频 {video_count} 个，共 {total} 个文件",
            "data": {"deleted_count": total, "image_count": image_count, "video_count": video_count}
        }

    except Exception as e:
        logger.error(f"[Admin] 清理缓存异常: {e}")
        raise HTTPException(status_code=500, detail={"error": f"清理失败: {e}", "code": "CACHE_CLEAR_ERROR"})


@router.post("/api/cache/clear/images")
async def clear_image_cache(_: bool = Depends(verify_admin_session)) -> Dict[str, Any]:
    """清理图片缓存"""
    try:
        logger.debug("[Admin] 清理图片缓存")

        count = 0
        if IMAGE_CACHE_DIR.exists():
            for file_path in IMAGE_CACHE_DIR.iterdir():
                if file_path.is_file():
                    try:
                        file_path.unlink()
                        count += 1
                    except Exception as e:
                        logger.error(f"[Admin] 删除失败: {file_path.name}, {e}")

        logger.debug(f"[Admin] 图片缓存清理完成: {count}个")
        return {"success": True, "message": f"成功清理图片缓存，删除 {count} 个文件", "data": {"deleted_count": count, "type": "images"}}

    except Exception as e:
        logger.error(f"[Admin] 清理图片缓存异常: {e}")
        raise HTTPException(status_code=500, detail={"error": f"清理失败: {e}", "code": "IMAGE_CACHE_CLEAR_ERROR"})


@router.post("/api/cache/clear/videos")
async def clear_video_cache(_: bool = Depends(verify_admin_session)) -> Dict[str, Any]:
    """清理视频缓存"""
    try:
        logger.debug("[Admin] 清理视频缓存")

        count = 0
        if VIDEO_CACHE_DIR.exists():
            for file_path in VIDEO_CACHE_DIR.iterdir():
                if file_path.is_file():
                    try:
                        file_path.unlink()
                        count += 1
                    except Exception as e:
                        logger.error(f"[Admin] 删除失败: {file_path.name}, {e}")

        logger.debug(f"[Admin] 视频缓存清理完成: {count}个")
        return {"success": True, "message": f"成功清理视频缓存，删除 {count} 个文件", "data": {"deleted_count": count, "type": "videos"}}

    except Exception as e:
        logger.error(f"[Admin] 清理视频缓存异常: {e}")
        raise HTTPException(status_code=500, detail={"error": f"清理失败: {e}", "code": "VIDEO_CACHE_CLEAR_ERROR"})


@router.get("/api/stats")
async def get_stats(_: bool = Depends(verify_admin_session)) -> Dict[str, Any]:
    """获取统计信息"""
    try:
        logger.debug("[Admin] 开始获取统计信息")

        all_tokens = token_manager.get_tokens()
        normal_stats = calculate_token_stats(all_tokens.get(TokenType.NORMAL.value, {}), "normal")
        super_stats = calculate_token_stats(all_tokens.get(TokenType.SUPER.value, {}), "super")
        total = normal_stats["total"] + super_stats["total"]

        logger.debug(f"[Admin] 统计信息获取成功 - 普通Token: {normal_stats['total']}, Super Token: {super_stats['total']}, 总计: {total}")
        return {"success": True, "data": {"normal": normal_stats, "super": super_stats, "total": total}}

    except Exception as e:
        logger.error(f"[Admin] 获取统计信息异常: {e}")
        raise HTTPException(status_code=500, detail={"error": f"获取失败: {e}", "code": "STATS_ERROR"})


@router.get("/api/storage/mode")
async def get_storage_mode(_: bool = Depends(verify_admin_session)) -> Dict[str, Any]:
    """获取存储模式"""
    try:
        logger.debug("[Admin] 获取存储模式")
        import os
        mode = os.getenv("STORAGE_MODE", "file").upper()
        return {"success": True, "data": {"mode": mode}}
    except Exception as e:
        logger.error(f"[Admin] 获取存储模式异常: {e}")
        raise HTTPException(status_code=500, detail={"error": f"获取失败: {e}", "code": "STORAGE_MODE_ERROR"})


@router.post("/api/tokens/tags")
async def update_token_tags(request: UpdateTokenTagsRequest, _: bool = Depends(verify_admin_session)) -> Dict[str, Any]:
    """更新Token标签"""
    try:
        logger.debug(f"[Admin] 更新Token标签: {request.token[:10]}..., {request.tags}")

        token_type = validate_token_type(request.token_type)
        await token_manager.update_token_tags(request.token, token_type, request.tags)

        logger.debug(f"[Admin] Token标签更新成功: {request.token[:10]}...")
        return {"success": True, "message": "标签更新成功", "tags": request.tags}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[Admin] Token标签更新异常: {e}")
        raise HTTPException(status_code=500, detail={"error": f"更新失败: {e}", "code": "UPDATE_TAGS_ERROR"})


@router.get("/api/tokens/tags/all")
async def get_all_tags(_: bool = Depends(verify_admin_session)) -> Dict[str, Any]:
    """获取所有标签"""
    try:
        logger.debug("[Admin] 获取所有标签")

        all_tokens = token_manager.get_tokens()
        tags_set = set()

        for token_type_data in all_tokens.values():
            for token_data in token_type_data.values():
                tags = token_data.get("tags", [])
                if isinstance(tags, list):
                    tags_set.update(tags)

        tags_list = sorted(list(tags_set))
        logger.debug(f"[Admin] 标签获取成功: {len(tags_list)}个")
        return {"success": True, "data": tags_list}

    except Exception as e:
        logger.error(f"[Admin] 获取标签异常: {e}")
        raise HTTPException(status_code=500, detail={"error": f"获取失败: {e}", "code": "GET_TAGS_ERROR"})


@router.post("/api/tokens/note")
async def update_token_note(request: UpdateTokenNoteRequest, _: bool = Depends(verify_admin_session)) -> Dict[str, Any]:
    """更新Token备注"""
    try:
        logger.debug(f"[Admin] 更新Token备注: {request.token[:10]}...")

        token_type = validate_token_type(request.token_type)
        await token_manager.update_token_note(request.token, token_type, request.note)

        logger.debug(f"[Admin] Token备注更新成功: {request.token[:10]}...")
        return {"success": True, "message": "备注更新成功", "note": request.note}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[Admin] Token备注更新异常: {e}")
        raise HTTPException(status_code=500, detail={"error": f"更新失败: {e}", "code": "UPDATE_NOTE_ERROR"})


@router.post("/api/tokens/test")
async def test_token(request: TestTokenRequest, _: bool = Depends(verify_admin_session)) -> Dict[str, Any]:
    """测试Token可用性"""
    try:
        logger.debug(f"[Admin] 测试Token: {request.token[:10]}...")

        token_type = validate_token_type(request.token_type)
        auth_token = f"sso-rw={request.token};sso={request.token}"

        result = await token_manager.check_limits(auth_token, "grok-4-fast")

        if result:
            logger.debug(f"[Admin] Token测试成功: {request.token[:10]}...")
            return {
                "success": True,
                "message": "Token有效",
                "data": {
                    "valid": True,
                    "remaining_queries": result.get("remainingTokens", -1),
                    "limit": result.get("limit", -1)
                }
            }
        else:
            logger.warning(f"[Admin] Token测试失败: {request.token[:10]}...")

            all_tokens = token_manager.get_tokens()
            token_data = all_tokens.get(token_type.value, {}).get(request.token)

            if token_data:
                if token_data.get("status") == "expired":
                    return {"success": False, "message": "Token已失效", "data": {"valid": False, "error_type": "expired", "error_code": 401}}
                elif token_data.get("remainingQueries") == 0:
                    return {"success": False, "message": "Token已被限流", "data": {"valid": False, "error_type": "limited", "error_code": "other"}}
                else:
                    return {"success": False, "message": "服务器被block或网络错误", "data": {"valid": False, "error_type": "blocked", "error_code": 403}}
            else:
                return {"success": False, "message": "Token数据异常", "data": {"valid": False, "error_type": "unknown", "error_code": "data_error"}}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[Admin] Token测试异常: {e}")
        raise HTTPException(status_code=500, detail={"error": f"测试失败: {e}", "code": "TEST_TOKEN_ERROR"})


@router.post("/api/tokens/test/batch")
async def batch_test_tokens(request: BatchTestTokensRequest, _: bool = Depends(verify_admin_session)) -> Dict[str, Any]:
    """批量测试Token可用性"""
    import asyncio
    
    try:
        # 根据模式获取待测试的 token 列表
        tokens_to_test: List[Dict[str, str]] = []
        
        if request.mode == "selected":
            if not request.tokens:
                raise HTTPException(status_code=400, detail={"error": "未选择任何Token", "code": "NO_TOKENS"})
            tokens_to_test = request.tokens
            
        elif request.mode == "all":
            all_tokens = token_manager.get_tokens()
            # 存储键到前端键的映射
            type_mapping = {TokenType.NORMAL.value: "sso", TokenType.SUPER.value: "ssoSuper"}
            for storage_type, api_type in type_mapping.items():
                for token in all_tokens.get(storage_type, {}).keys():
                    tokens_to_test.append({"token": token, "token_type": api_type})

        elif request.mode == "filter":
            all_tokens = token_manager.get_tokens()
            # 存储键到前端键的映射
            type_mapping = {TokenType.NORMAL.value: "sso", TokenType.SUPER.value: "ssoSuper"}
            for storage_type, api_type in type_mapping.items():
                if request.token_type and request.token_type != api_type:
                    continue
                for token, data in all_tokens.get(storage_type, {}).items():
                    if request.status:
                        token_status = get_token_status(data)
                        if token_status != request.status:
                            continue
                    tokens_to_test.append({"token": token, "token_type": api_type})
        else:
            raise HTTPException(status_code=400, detail={"error": "无效的测试模式", "code": "INVALID_MODE"})
        
        if not tokens_to_test:
            return {"success": True, "data": {"total": 0, "valid": 0, "invalid": 0, "results": []}}
        
        logger.info(f"[Admin] 开始批量测试 {len(tokens_to_test)} 个Token，并发数: {request.concurrency}")
        
        # 并发控制
        semaphore = asyncio.Semaphore(request.concurrency)
        results = []
        
        async def test_single_token(token_info: Dict[str, str]) -> Dict[str, Any]:
            async with semaphore:
                token = token_info["token"]
                token_type = token_info["token_type"]
                token_short = token[:10] + "..."
                
                try:
                    auth_token = f"sso-rw={token};sso={token}"
                    result = await token_manager.check_limits(auth_token, "grok-4-fast")
                    
                    if result:
                        return {
                            "token": token_short,
                            "token_type": token_type,
                            "valid": True,
                            "remaining": result.get("remainingTokens", -1),
                            "message": "Token有效"
                        }
                    else:
                        # 获取详细错误信息
                        all_tokens = token_manager.get_tokens()
                        token_data = all_tokens.get(token_type, {}).get(token)
                        
                        error_type = "unknown"
                        message = "Token无效"
                        
                        if token_data:
                            if token_data.get("status") == "expired":
                                error_type = "expired"
                                message = "Token已失效"
                            elif token_data.get("remainingQueries") == 0:
                                error_type = "limited"
                                message = "Token已被限流"
                            else:
                                error_type = "blocked"
                                message = "服务器被block或网络错误"
                        
                        return {
                            "token": token_short,
                            "token_type": token_type,
                            "valid": False,
                            "error_type": error_type,
                            "message": message
                        }
                        
                except Exception as e:
                    logger.error(f"[Admin] 测试Token异常 {token_short}: {e}")
                    return {
                        "token": token_short,
                        "token_type": token_type,
                        "valid": False,
                        "error_type": "error",
                        "message": f"测试异常: {str(e)[:50]}"
                    }
        
        # 并发执行所有测试
        tasks = [test_single_token(t) for t in tokens_to_test]
        results = await asyncio.gather(*tasks)
        
        # 统计结果
        valid_count = sum(1 for r in results if r["valid"])
        invalid_count = len(results) - valid_count
        
        logger.info(f"[Admin] 批量测试完成: 总计 {len(results)}, 有效 {valid_count}, 无效 {invalid_count}")
        
        return {
            "success": True,
            "data": {
                "total": len(results),
                "valid": valid_count,
                "invalid": invalid_count,
                "results": results
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[Admin] 批量测试异常: {e}")
        raise HTTPException(status_code=500, detail={"error": f"批量测试失败: {e}", "code": "BATCH_TEST_ERROR"})
