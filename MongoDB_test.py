from pymongo import MongoClient
from datetime import datetime


# MongoDB连接配置
client = MongoClient("mongodb+srv://3375403643:xjy1232004@heartflowcluster.xmkes.mongodb.net", tls=True,  # 启用TLS
    tlsAllowInvalidCertificates=True)  # 忽略证书验证（仅开发环境）)
db = client.get_database('HeartFlow')

users_collection = db.users
chats_collection = db.chats

def load_session_data(user_id, session_id):
    # 从数据库获取聊天记录
    chat = chats_collection.find_one({"userId": user_id})

    if chat and "messages" in chat:
        # 过滤出属于当前会话的消息
        session_messages = [msg for msg in chat["messages"] if msg.get("session_id") == session_id]
        return session_messages
    else:
        return []

def register_user(username, email, password):
    # 检查用户是否已经存在
    if users_collection.find_one({"email": email}):
        return {"status": "error", "message": "Email already registered"}

    # 对密码进行加密
    hashed_password = password

    # 插入新用户数据
    user_data = {
        "username": username,
        "email": email,
        "password": hashed_password
    }
    result = users_collection.insert_one(user_data)
    user_id = result.inserted_id

    # 初始化聊天记录
    chats_collection.insert_one({
        "userId": user_id,
        "messages": []
    })

    return {"status": "success", "message": "User registered successfully", "user_id": str(user_id)}


def add_chat_message(user_id, session_id, role, message):
    """
    向用户的聊天记录中添加一条消息。

    :param user_id: 用户的唯一标识符
    :param session_id: 会话的唯一标识符或发送者的角色
    :param role: 发送者角色（例如 "user", "assistant"）
    :param message: 消息内容
    """
    chat = chats_collection.find_one_and_update(
        {"userId": user_id},
        {"$push": {"messages": {
            "session_id": session_id,  # 假设你想保存会话ID
            "role": role,  # 角色信息，如"user"或"assistant"
            "message": message,
            "timestamp": datetime.now()
        }}},
        upsert=True  # 如果没有找到匹配的文档，则插入新文档
    )
    return chat


def get_chat_messages(user_id, session_id=None, skip=0, limit=10):
    """
    根据用户ID和可选的会话ID获取聊天消息。

    :param user_id: 用户的唯一标识符
    :param session_id: 会话的唯一标识符（可选）
    :param skip: 跳过的消息数量，默认为0
    :param limit: 返回的最大消息数量，默认为10
    :return: 消息列表
    """
    query = {"userId": user_id}

    # 如果提供了session_id，则添加到查询条件中
    if session_id is not None:
        query["messages.session_id"] = session_id

    chat = chats_collection.find_one(query, {"messages": 1})

    if chat and "messages" in chat:
        messages = chat["messages"]

        # 如果有session_id，则只过滤出对应session的消息
        if session_id is not None:
            messages = [msg for msg in messages if msg.get("session_id") == session_id]

        # 确保skip和limit在合理范围内
        start = max(0, min(skip, len(messages)))
        end = max(start, min(skip + limit, len(messages)))

        return messages[start:end]
    else:
        return []


def login_user(email, password):
    # 查找用户
    user = users_collection.find_one({"email": email})
    if not user:
        return {"status": "error", "message": "No such user"}

    # 核对密码
    if password == user['password']:
        # 将用户信息存入session state
        return{
            "status": "success",
            "_id": str(user["_id"]),
            "username": user["username"],
            "email": user["email"]
        }
    else:
        return {"status": "error", "message": "Invalid credentials"}