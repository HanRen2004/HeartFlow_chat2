import streamlit as st
import requests
import uuid
from langchain.chains import LLMChain
from langchain.memory import ConversationBufferMemory
from langchain.tools import tool
from langchain_community.llms.tongyi import Tongyi
import os
from langchain.agents import initialize_agent, AgentType, Tool
from langchain_core.prompts import PromptTemplate
from openai import OpenAI
from langchain_openai import ChatOpenAI
from streamlit_webrtc import webrtc_streamer, RTCConfiguration
from flask import Flask, request, jsonify
from flask_cors import CORS
import base64
import threading
import time
from datetime import datetime,timedelta
from langchain.tools import BaseTool
from typing import Any, Optional
from MongoDB_test import add_chat_message, get_chat_messages, login_user,register_user,load_session_data
from pymongo import MongoClient

# 定义全局字符串，用于保存用户当前的情感信息
current_user_emotion = ""
current_username = " "

def call_yolo_predict(image_path):
    # 将相对路径转换为绝对路径
    abs_image_path = os.path.abspath(image_path)

    url = "http://127.0.0.1:5003/predict"  # 根据实际情况调整URL
    with open(abs_image_path, 'rb') as img:
        response = requests.post(url, files={'image': img})
        if response.status_code == 200:
            return response.json()
        else:
            print("Error:", response.status_code, response.text)
            return None
# ==================== 后端部分 (Flask) ====================
app = Flask(__name__)
CORS(app)  # 这将允许所有来源的请求

# 保存截图的目录
UPLOAD_FOLDER = "screenshots"
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@app.route('/upload_screenshot', methods=['POST'])
def upload_screenshot():
    data = request.json
    if not data or 'image' not in data:
        return jsonify({'error': 'No image data provided'}), 400

    # 解码 Base64 图像数据
    image_data = data['image'].split(",")[1]  # 去掉前缀
    image_bytes = base64.b64decode(image_data)

    # 获取当前时间并格式化为字符串
    current_time_str = datetime.now().strftime("%Y%m%d_%H%M%S")  # 格式化为年月日_时分秒

    # 保存图像
    file_name = f"screenshot_{current_time_str}.jpg"
    file_path = os.path.join(UPLOAD_FOLDER, file_name)
    with open(file_path, "wb") as f:
        f.write(image_bytes)

    result = call_yolo_predict(file_path)
    if result is not None:
        # 使用global关键字声明我们将使用全局变量
        global current_user_emotion
        current_user_emotion = result  # 更新全局变量
        print("预测结果:")
        print(current_user_emotion)

    return jsonify({'message': 'Screenshot saved successfully', 'file': file_path}), 200



# 启动 Flask 后端
def run_flask():
    app.run(port=5001)

# ==================== 前端部分 (Streamlit) ====================
st.set_page_config(page_title="心语星", page_icon="3")

st.markdown("""
    <style>
        /* 隐藏默认头像 */
        .css-17gblp5 img {
            display: none;
        }
        /* 自定义用户消息气泡 */
        .user-message {
            background-color: #ccffcc; /* 浅绿色背景 */
            color: black; /* 白色文字 */
            border-radius: 10px;
            padding: 10px;
            margin-left: auto; /* 对齐到右侧 */
            text-align: right;
            max-width: 70%;
            display: inline-block;
            clear: both;
        }
        /* 自定义机器人消息气泡 */
        .bot-message {
            background-color: white; /* 白色背景 */
            color: black; /* 黑色文字 */
            border-radius: 10px;
            padding: 10px;
            margin-right: auto; /* 对齐到左侧 */
            max-width: 70%;
            display: inline-block;
            clear: both;
        }
    </style>
""", unsafe_allow_html=True)


def show_login_register():
    """显示登录/注册界面及登出选项"""
    # 判断用户是否已登录且用户信息有效
    if 'current_user' in st.session_state and isinstance(st.session_state.current_user,
                                                         dict) and 'username' in st.session_state.current_user:
        # 显示欢迎信息和登出按钮
        st.write(f"Welcome, {st.session_state.current_user.get('username', 'User')}!")
        global current_username
        current_username=st.session_state.current_user.get('username', 'User')

        if st.button("Logout"):
            del st.session_state['current_user']  # 清除当前用户状态
            st.rerun()  # 使用实验性rerun方法刷新页面，回到登录/注册界面

    else:
        # 用户未登录或用户信息无效时显示登录/注册界面
        with st.expander("Login/Register", expanded=True):
            choice = st.radio("Choose an action", ["Login", "Register"])

            if choice == "Login":
                email = st.text_input("Email")
                password = st.text_input("Password", type="password")

                if st.button("Login"):
                    result = login_user(email, password)
                    st.write(f"Attempting to log in with email: {email}")  # Debug output
                    st.write(f"Result from login_user: {result}")  # Debug output

                    if isinstance(result, dict) and "status" in result:
                        if result["status"] == "success":
                            # 确保仅保存必要的用户信息到session_state
                            st.session_state.current_user = {
                                '_id': result.get('_id'),
                                'username': result.get('username'),
                                'email': result.get('email')
                            }
                            st.success("Login successful!")
                            st.rerun()  # 使用实验性rerun方法刷新页面
                        else:
                            st.error(f"Error: {result.get('message', 'Failed to login.')}")
                    else:
                        st.error("Invalid response format from login_user.")

            elif choice == "Register":
                username = st.text_input("Username")
                email = st.text_input("Email")
                password = st.text_input("Password", type="password")

                if st.button("Register"):
                    result = register_user(username, email, password)
                    if result["status"] == "success":
                        st.success("Registration successful! You can now log in.")
                        st.rerun()  # 刷新页面，清除输入
                    else:
                        st.error(result["message"])


# 设置页面标题
st.title("心语星")

# 显示登录/注册界面
show_login_register()


# 在这里添加检查用户登录状态的逻辑
if 'current_user' not in st.session_state:
    st.error("Please log in to continue.")
else:
    current_messages = st.session_state.sessions[st.session_state.current_session_id]


# 初始化 session state 如果尚未初始化
if 'sessions' not in st.session_state:
    st.session_state.sessions = {}
if 'current_session_id' not in st.session_state:
    new_session_id = str(uuid.uuid4())
    st.session_state.sessions[new_session_id] = []
    st.session_state.current_session_id = new_session_id



# 示例：添加一条消息到当前会话（通常这是由其他函数调用的）
def add_message_to_session(role, content):
    if st.session_state.current_session_id not in st.session_state.sessions:
        st.session_state.sessions[st.session_state.current_session_id] = []

    st.session_state.sessions[st.session_state.current_session_id].append({
        "role": role,
        "message": content,  # 注意这里是 "message" 而不是 "content"
        "timestamp": datetime.now().isoformat()
    })

def get_current_user_id():
    """
       根据用户名从MongoDB的users集合中查找对应的用户ID。

       :param username: 用户名
       :return: 对应的用户ID，如果未找到则返回None
       """
    user = users_collection.find_one({"username": current_username})
    if user:
        return user.get("userid")  # 或者直接返回user["userid"]，取决于你的数据结构
    else:
        print(f"User with username {current_username} not found.")
        return None

# 显示当前会话中的所有消息
def display_chat():
    if st.session_state.current_session_id in st.session_state.sessions:
        current_messages = st.session_state.sessions[st.session_state.current_session_id]
    else:
        # 如果当前会话没有在 session_state 中，则尝试从数据库加载
        user_id = get_current_user_id()
        current_messages = load_session_data(user_id, st.session_state.current_session_id)
        st.session_state.sessions[st.session_state.current_session_id] = current_messages

    for message in current_messages:
            role = message.get("role", "")
            content = message.get("message", "")  # 使用 .get() 方法并提供默认值

            if role == "user":
                st.markdown(f'<div class="user-message">{content}</div>', unsafe_allow_html=True)
            elif role == "assistant":
                st.markdown(f'<div class="bot-message">{content}</div>', unsafe_allow_html=True)


# 切换会话的函数
def switch_session(session_id):
    """
    切换当前会话，并重新加载新会话的数据。

    :param session_id: 新的会话ID
    """
    # 更新当前会话ID
    st.session_state.current_session_id = session_id

    # 获取用户ID（这里假设你有方法获取当前用户ID）
    user_id = get_current_user_id()  # 需要替换为实际获取用户ID的方法

    # 如果新会话不在 session_state 中，则从数据库加载
    if session_id not in st.session_state.sessions:
        st.session_state.sessions[session_id] = load_session_data(user_id, session_id)

# 调试信息：打印当前会话的消息以确认结构
def debug_print_current_messages():
    if st.session_state.current_session_id in st.session_state.sessions:
        current_messages = st.session_state.sessions[st.session_state.current_session_id]
        print("Current messages:", current_messages)  # 打印消息列表以进行调试


# HTML和JavaScript代码，用于访问摄像头并播放视频流
html_content = """
<div>
    <button id="toggleCameraBtn" style="width: 100%; margin-bottom: 10px;">开启摄像头</button>
    <div id="video-container" style="width: 100%; height: 150px; display:none;">
        <video id="video" autoplay playsinline style="width: 100%; height: 100%;"></video>
    </div>
</div>
<script>
    const video = document.getElementById('video');
    const videoContainer = document.getElementById('video-container');
    const toggleCameraBtn = document.getElementById('toggleCameraBtn');
    let streamStarted = false;
    let intervalId;

    async function startCamera() {
        try {
            const stream = await navigator.mediaDevices.getUserMedia({ video: { width: 200, height: 150 } });
            video.srcObject = stream;
            streamStarted = true;
            videoContainer.style.display = 'block';
            toggleCameraBtn.innerText = '关闭摄像头';

            // 每隔5秒截取一张图片并发送到后端
            intervalId = setInterval(() => captureAndSendFrame(), 5000);
        } catch (err) {
            console.error("Error accessing the camera: ", err);
        }
    }

    function stopCamera() {
        if (streamStarted && video.srcObject) {
            clearInterval(intervalId); // 停止定时器
            const tracks = video.srcObject.getTracks();
            tracks.forEach(track => track.stop());
            video.srcObject = null;
            streamStarted = false;
            videoContainer.style.display = 'none';
            toggleCameraBtn.innerText = '开启摄像头';
        }
    }

    function captureAndSendFrame() {
        const canvas = document.createElement('canvas');
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        const ctx = canvas.getContext('2d');
        ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
        const dataURL = canvas.toDataURL('image/jpeg');

        // 将图像数据发送到后端
        fetch('http://localhost:5001/upload_screenshot', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ image: dataURL })
        }).then(response => response.json())
          .then(data => console.log('Success:', data))
          .catch((error) => console.error('Error:', error));
    }

    toggleCameraBtn.addEventListener('click', () => {
        if (!streamStarted) {
            startCamera();
        } else {
            stopCamera();
        }
    });
</script>
"""

def get_current_user():
    """
    返回当前登录用户的信息。
    如果用户未登录，则返回None。
    """
    return st.session_state.get("current_user")


def create_new_session():
    new_session_id = str(uuid.uuid4())
    st.session_state.sessions[new_session_id] = []
    st.session_state.current_session_id = new_session_id


def select_session(session_id):
    current_user = get_current_user()
    if not current_user:
        st.error("No user is logged in.")
        return

    user_id = current_user.get("_id")
    if not user_id:
        st.error("User ID is missing.")
        return

    # 从MongoDB加载聊天记录
    messages = get_chat_messages(user_id, session_id)

    # 更新当前会话的消息列表
    st.session_state.sessions[session_id] = messages
    st.session_state.current_session_id = session_id


# 使用Streamlit的components功能嵌入自定义HTML/JS代码
with st.sidebar:
    st.header("会话管理")

    if st.button("新建会话"):
        create_new_session()

    search_query = st.text_input("搜索会话...")

    st.subheader("会话列表")
    for session_id, messages in st.session_state.sessions.items():
        timestamp = "2023/3/15 22:15:27"  # 示例时间戳，实际应用中应动态生成或从持久化存储获取
        if st.button(f"{session_id[:8]} - {timestamp}", key=f"select_{session_id}"):
            select_session(session_id)

    # 在侧边栏的下半部分添加摄像头功能
    st.markdown("---")  # 分隔线
    st.write("摄像头功能")
    st.components.v1.html(html_content, height=200)


current_messages = st.session_state.sessions[st.session_state.current_session_id]

# 设置 API 密钥
os.environ["DASHSCOPE_API_KEY"] = os.getenv("DASHSCOPE_API_KEY", "sk-38a6f574d6c6483eae5c32998a16822a")
os.environ["DASHSCOPE_API_BASE"] = os.getenv("DASHSCOPE_API_BASE", "https://dashscope.aliyuncs.com/compatible-mode/v1")

llm_e = ChatOpenAI(
    model="qwen-max",
    temperature=0.8,
    api_key=os.getenv("DASHSCOPE_API_KEY"),
    base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
)


class EmotionAnalysisTool(BaseTool):
    # 添加类型注解
    name: str = "emotion_analysis"
    description: str = "分析用户最近一次提供的图片中的情感状态，并给出回答建议"
    llm: ChatOpenAI  # 将llm_e作为类的属性

    def __init__(self, llm_instance: ChatOpenAI, **data: Any):
        # 将llm_instance直接赋值给llm字段
        data['llm'] = llm_instance
        super().__init__(**data)

    def _run(self, user_id: str) -> str:
        """根据用户ID获取其最新emotion信息，并使用LLM生成回答建议"""
        global current_user_emotion  # 使用global关键字声明我们将使用全局变量

        if not current_user_emotion:
            return "未找到您的情感分析记录，请先提供一张图片进行分析。"

        # 解析时间戳
        try:
            parts = current_user_emotion.split("分析时间: ")
            emotion_info = parts[0].strip()
            timestamp_str = parts[1].split("。")[0].strip()  # 获取时间戳部分并去除句号

            # 将时间戳字符串转换为datetime对象
            analysis_time = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")

            # 检查时间差
            now = datetime.now()
            if now - analysis_time > timedelta(seconds=10):
                current_user_emotion = ""
                # return "情感分析结果已过期，请重新提供一张图片进行分析。"

            # 构造提示消息
            eprompt = f"根据以下情感分析结果为用户提供回应建议：\n{emotion_info} 分析时间: {timestamp_str}"

            # 调用LLM生成回答建议
            eresponse_suggestion = self.llm(eprompt)

            return eresponse_suggestion
        except Exception as e:
            print(f"Error parsing current_user_emotion: {e}")
            return "未能正确解析情感分析结果，请稍后再试或重新进行情感分析。"

    async def _arun(self, user_id: str) -> str:
        """异步版本的_run方法"""
        raise NotImplementedError("此工具不支持异步操作")

# 创建网络搜索工具
@tool
def bocha_websearch_tool(query: str, count: int = 20) -> str:
    """
    使用Bocha Web Search API 网页搜索
    """
    url = 'https://api.bochaai.com/v1/web-search'
    headers = {
        'Authorization': f'Bearer sk-6012a020f72d4c26ae5ad415300c94f9',
        'Content-Type': 'application/json'
    }
    data = {
        "query": query,
        "freshness": "noLimit",
        "summary": True,
        "count": count
    }

    response = requests.post(url, headers=headers, json=data)
    if response.status_code == 200:
        try:
            json_response = response.json()
            if json_response["code"] == 200 and json_response.get("data"):
                webpages = json_response["data"]["webPages"]["value"]
                if not webpages:
                    return "未找到相关结果."
                formatted_results = ""
                for idx, page in enumerate(webpages, start=1):
                    formatted_results += (
                        f"引用：{idx}\n"
                        f"标题：{page['name']}\n"
                        f"URL: {page['url']}\n"
                        f"摘要：{page['summary']}\n"
                        f"网站名称：{page['siteName']}\n"
                        f"网站图标：{page['siteIcon']}\n"
                        f"发布时间：{page['dateLastCrawled']}\n\n"
                    )
                return formatted_results.strip()
            else:
                return f"搜索失败，原因：{json_response.get('message', '未知错误')}"
        except Exception as e:
            return f"处理搜索结果失败，原因是：{str(e)}\n原始响应：{response.text}"
    else:
        return f"搜索API请求失败，状态码：{response.status_code}, 错误信息：{response.text}"


memory = ConversationBufferMemory(memory_key="chat_history")

llm = ChatOpenAI(
    model="qwen-max",
    temperature=0.8,
    api_key=os.getenv("DASHSCOPE_API_KEY"),
    base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
)

bocha_tool = Tool(
    name="Bocha Web Search",
    func=bocha_websearch_tool,
    description="使用Bocha Web Search API进行搜索互联网网页，输入应为搜索查询字符串，输出将返回搜索结果的详细信息。包括网页标题、网页URL",
)

emotion_tool = EmotionAnalysisTool(llm_instance=llm_e)



agent_prompt = """
作为一个高情商的对话伙伴，对于用户提出的任何问题，你都能够提供既得体又关切的回答。现在，请针对以下问题展现你的高情商回应：“${question}”，并确保在回复中充分考虑到对方的情绪状态和潜在需求。注意：对于用户提出的每一个问题，你都应该在文末加上你的搜索结果
注意结合用户当前具体的心理状况，你可以使用emotion_tool
"""

agent = initialize_agent(
    tools=[bocha_tool,emotion_tool],
    llm=llm,
    agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
    verbose=True,
    agent_kwargs={"agent_prompt": agent_prompt, 'memory': memory}
)

prompt_template = """
作为一个高情商的对话伙伴，对于用户提出的任何问题，你都能够提供既得体又关切的回答。现在，请针对以下问题展现你的高情商回应：“${question}”，并确保在回复中充分考虑到对方的情绪状态和潜在需求。注意：对于用户提出的每一个问题，你都应该在文末加上你的搜索结果
"""

prompt = PromptTemplate(
    input_variables=["question", 'response'],
    template=prompt_template
)

llm_chat = ChatOpenAI(
    model="qwen-max-latest",
    temperature=0.8,
    api_key=os.getenv("DASHSCOPE_API_KEY"),
    base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
)

chain = LLMChain(llm=llm_chat, prompt=prompt)

if user_question := st.chat_input("请输入你的问题"):
    current_session_id = st.session_state.current_session_id
    # 假设你已经有一个获取当前登录用户的函数get_current_user()
    user_id = get_current_user().get("_id")  # 获取当前用户的ID

    # 在内存中添加消息
    st.session_state.sessions[current_session_id].append({"role": "user", "content": user_question})

    # 将消息保存到MongoDB
    add_chat_message(user_id, current_session_id, "user", user_question)

    with st.chat_message("user"):
        st.markdown(user_question)

    response = agent.run(user_question)

    # 在内存中添加机器人的回复
    st.session_state.sessions[current_session_id].append({"role": "assistant", "content": response})

    # 将回复保存到MongoDB
    add_chat_message(user_id, current_session_id, "assistant", response)

    with st.chat_message("assistant"):
        st.markdown(response)

# ==================== 主程序入口 ====================
if __name__ == "__main__":
    # 启动 Flask 后端
    flask_thread = threading.Thread(target=run_flask, daemon=True)
    flask_thread.start()

    # Streamlit 前端无需显式调用 st.run()
# 直接运行脚本时，Streamlit 会自动启动前端

