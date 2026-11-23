import { useState } from 'react'

function getCookie(name) {
  return document.cookie
    .split('; ')
    .find(row => row.startsWith(name + '='))
    ?.split('=')[1]
}

export default function App() {
  const [username, setUsername] = useState('alice')
  const [password, setPassword] = useState('Original123!')
  const [newPassword, setNewPassword] = useState('Normal456!')
  const [result, setResult] = useState('等待操作')

  async function call(path, data) {
    try {
      const options = {
        method: data === undefined ? 'GET' : 'POST',
        credentials: 'include',
      }

      if (data !== undefined) {
        // 首次 POST 前浏览器可能还没有 csrf_token Cookie，先发一个 GET 让后端下发
        if (!getCookie('csrf_token')) {
          await fetch('/api/me', { credentials: 'include' })
        }
        options.headers = {
          'Content-Type': 'application/x-www-form-urlencoded',
          'X-CSRF-Token': getCookie('csrf_token'),
        }
        options.body = new URLSearchParams(data)
      }

      const response = await fetch(`/api/${path}`, options)
      const body = await response.json()

      setResult(
        `HTTP ${response.status}\n${JSON.stringify(body, null, 2)}`
      )
    } catch (error) {
      setResult(`请求失败：${error.message}`)
    }
  }

  return (
    <main style={{ maxWidth: 640, margin: '40px auto', padding: 24 }}>
      <h1>React + Flask CSRF 靶场</h1>
      <p>本地教学环境：故意未实现 CSRF 防护。</p>

      <p>
        <label>
          用户名：
          <input
            value={username}
            onChange={e => setUsername(e.target.value)}
          />
        </label>
      </p>

      <p>
        <label>
          登录密码：
          <input
            type="password"
            value={password}
            onChange={e => setPassword(e.target.value)}
          />
        </label>
      </p>

      <p>
        <button onClick={() => call('register', { username, password })}>
          注册
        </button>
        {' '}
        <button onClick={() => call('login', { username, password })}>
          登录
        </button>
        {' '}
        <button onClick={() => call('me')}>
          查询当前用户
        </button>
        {' '}
        <button onClick={() => call('logout', {})}>
          退出
        </button>
      </p>

      <hr />

      <p>
        <label>
          新密码：
          <input
            type="password"
            value={newPassword}
            onChange={e => setNewPassword(e.target.value)}
          />
        </label>
      </p>

      <button
        onClick={() =>
          call('change-password', { new_password: newPassword })
        }
      >
        修改密码
      </button>

      <pre style={{ whiteSpace: 'pre-wrap' }}>{result}</pre>
    </main>
  )
}