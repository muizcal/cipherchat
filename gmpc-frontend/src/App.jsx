import React, { useState, useEffect, useRef } from "react";
import nacl from "tweetnacl";
import naclUtil from "tweetnacl-util";

// 🔑 API base URL
// - When running locally, set API = "http://localhost:4000"
// - When deployed with backend + frontend on same server, leave API = ""
const API = "";

export default function App() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");
  const [messages, setMessages] = useState([]);
  const [users, setUsers] = useState([]);
  const [recipients, setRecipients] = useState([]);
  const [publicKey, setPublicKey] = useState("");
  const [loggedIn, setLoggedIn] = useState(false);

  const feedRef = useRef(null);

  useEffect(() => {
    if (loggedIn) {
      fetchUsers();
      fetchMessages(username);
      const interval = setInterval(() => fetchMessages(username), 5000);
      return () => clearInterval(interval);
    }
  }, [loggedIn, username]);

  useEffect(() => {
    if (feedRef.current) feedRef.current.scrollTop = feedRef.current.scrollHeight;
  }, [messages]);

  // ----------------------
  // USER AUTH FUNCTIONS
  // ----------------------

  const signup = async () => {
    if (!username.trim() || !password.trim())
      return alert("Enter username & password!");

    // Check if keypair already exists
    let privKey = localStorage.getItem("privateKey");
    let pubKey = localStorage.getItem("publicKey");

    if (!privKey || !pubKey) {
      // Generate key pair only once
      const keyPair = nacl.box.keyPair();
      pubKey = naclUtil.encodeBase64(keyPair.publicKey);
      privKey = naclUtil.encodeBase64(keyPair.secretKey);

      localStorage.setItem("privateKey", privKey);
      localStorage.setItem("publicKey", pubKey);
    }

    setPublicKey(pubKey);

    try {
      const res = await fetch(`${API}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password, publicKey: pubKey }),
      });
      const data = await res.json();
      if (!res.ok || data.error) {
        alert(data.error || "Signup failed");
        return;
      }
      setLoggedIn(true);
      alert(
        `Welcome to CipherChat, ${username}!\n\n🔑 Your messages are end-to-end encrypted.\n\n📌 How it works:\n- Each account has a permanent cryptographic keypair.\n- Messages are encrypted with the recipient’s public key.\n- Only the recipient can decrypt with their private key.\n\n⚠️ Don’t clear your browser storage, or you’ll lose your private key and won’t be able to read old messages.`
      );
    } catch (err) {
      alert("Error signing up: " + err.message);
    }
  };

  const login = async () => {
    if (!username.trim() || !password.trim())
      return alert("Enter username & password!");
    try {
      const res = await fetch(`${API}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json();
      if (!res.ok || data.error) {
        return alert(data.error || "Login failed");
      }

      // Restore keys from localStorage
      let privKey = localStorage.getItem("privateKey");
      let pubKey = localStorage.getItem("publicKey");

      if (!privKey || !pubKey) {
        alert(
          "No stored keys found. Please sign up again to generate a keypair."
        );
        return;
      }

      setPublicKey(pubKey);
      setLoggedIn(true);
    } catch (err) {
      alert("Error logging in: " + err.message);
    }
  };

  const logout = () => {
    setLoggedIn(false);
    setUsername("");
    setPassword("");
    setMessages([]);
    setRecipients([]);
  };

  // ----------------------
  // FETCH USERS & MESSAGES
  // ----------------------

  const fetchUsers = async () => {
    try {
      const res = await fetch(`${API}/users`);
      const data = await res.json();
      setUsers(data);
    } catch (err) {
      console.error("Error fetching users:", err);
    }
  };

  const fetchMessages = async (user) => {
    if (!user) return;
    try {
      const res = await fetch(`${API}/messages?username=${user}`);
      const data = await res.json();
      const privKeyBase64 = localStorage.getItem("privateKey");
      if (!privKeyBase64) return;

      const privKey = naclUtil.decodeBase64(privKeyBase64);
      const decrypted = data.map((msg) => {
        let text = "[Unable to decrypt]";
        try {
          const decryptedBytes = nacl.box.open(
            naclUtil.decodeBase64(msg.encryptedMessage),
            naclUtil.decodeBase64(msg.nonce),
            naclUtil.decodeBase64(msg.senderPublicKey),
            privKey
          );
          if (decryptedBytes) text = naclUtil.encodeUTF8(decryptedBytes);
        } catch {}
        return { ...msg, text };
      });
      setMessages(decrypted.reverse());
    } catch (err) {
      console.error("Error fetching messages:", err);
    }
  };

  // ----------------------
  // SEND MESSAGE
  // ----------------------

  const sendMessage = async () => {
    if (!message.trim()) return alert("Type a message!");
    if (!recipients.length) return alert("Select at least one recipient!");
    const privKey = naclUtil.decodeBase64(localStorage.getItem("privateKey"));

    try {
      const encryptedMessages = await Promise.all(
        recipients.map(async (recipient) => {
          const resKey = await fetch(`${API}/publicKey?username=${recipient}`);
          if (!resKey.ok) throw new Error(`Recipient ${recipient} not found`);
          const dataKey = await resKey.json();
          const recipientPubKey = naclUtil.decodeBase64(dataKey.publicKey);

          const nonce = nacl.randomBytes(nacl.box.nonceLength);
          const encryptedMessage = nacl.box(
            naclUtil.decodeUTF8(message),
            nonce,
            recipientPubKey,
            privKey
          );

          return {
            recipient,
            encryptedMessage: naclUtil.encodeBase64(encryptedMessage),
            nonce: naclUtil.encodeBase64(nonce),
            senderPublicKey: publicKey,
          };
        })
      );

      const resSend = await fetch(`${API}/send`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sender: username, encryptedMessages }),
      });

      if (!resSend.ok) throw new Error("Failed to send message");

      setMessage("");
      setRecipients([]);
      fetchMessages(username);
    } catch (err) {
      alert("Error sending message: " + err.message);
      console.error(err);
    }
  };

  // ----------------------
  // RESET FEED
  // ----------------------

  const resetFeed = async () => {
    try {
      const res = await fetch(`${API}/reset`, { method: "POST" });
      if (!res.ok) throw new Error("Reset failed");
      setMessages([]);
    } catch (err) {
      alert("Error resetting feed: " + err.message);
    }
  };

  // ----------------------
  // RENDER
  // ----------------------

  if (!loggedIn) {
    return (
      <div style={styles.page}>
        <header style={styles.header}>
          <img src="/arcium.jpg" alt="Arcium Logo" style={styles.logo} />
          <h1 style={styles.title}>CipherChat</h1>
          <p style={styles.subtitle}>
            End-to-end encrypted messaging. Built on Arcium.
          </p>
        </header>
        <div style={styles.authBox}>
          <p style={styles.instructions}>
            📌 How CipherChat works:
            <br />
            - Every account gets a unique cryptographic keypair.
            <br />
            - Messages are encrypted with the recipient’s public key.
            <br />
            - Only the recipient can decrypt them.
            <br />
            ⚠️ Don’t clear your browser storage, or you’ll lose your private key
            (and won’t be able to read old messages).
          </p>
          <input
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            style={styles.input}
          />
          <input
            placeholder="Password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            style={styles.input}
          />
          <div style={{ display: "flex", gap: "10px", marginTop: "10px" }}>
            <button onClick={signup} style={styles.button}>
              Sign Up
            </button>
            <button onClick={login} style={styles.button}>
              Log In
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Logged in interface
  return (
    <div style={styles.page}>
      <header style={styles.header}>
        <img src="/arcium.jpg" alt="Arcium Logo" style={styles.logo} />
        <h1 style={styles.title}>CipherChat</h1>
        <p style={styles.subtitle}>
          Send messages privately. End-to-end encrypted. Built on Arcium.
        </p>
        <button onClick={logout} style={styles.logoutButton}>
          Logout
        </button>
      </header>

      <div style={styles.inputRow}>
        <select
          multiple
          value={recipients}
          onChange={(e) =>
            setRecipients(Array.from(e.target.selectedOptions, (opt) => opt.value))
          }
          style={{ ...styles.input, maxWidth: "250px" }}
        >
          {users.filter((u) => u !== username).map((u) => (
            <option key={u} value={u}>
              {u}
            </option>
          ))}
        </select>

        <input
          placeholder="Type your encrypted message..."
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          style={styles.input}
        />
        <button onClick={sendMessage} style={styles.button}>
          Send
        </button>
      </div>

      <div style={styles.resetRow}>
        <button onClick={resetFeed} style={styles.resetButton}>
          Reset Feed
        </button>
      </div>

      <div style={styles.feed} ref={feedRef}>
        {messages.map((msg) => (
          <div key={msg.id} style={styles.message}>
            <b style={{ color: "#c084fc" }}>{msg.sender}</b> ➤ {msg.text}
            <br />
            <small style={styles.timestamp}>
              {new Date(msg.ts).toLocaleTimeString()}
            </small>
          </div>
        ))}
      </div>
    </div>
  );
}

// ----------------------
// STYLES
// ----------------------
const styles = {
  page: {
    minHeight: "100vh",
    width: "100vw",
    display: "flex",
    flexDirection: "column",
    background: "#1a0826",
    color: "#f0eaff",
    fontFamily: "system-ui, sans-serif",
    margin: 0,
    padding: 0,
  },
  header: {
    textAlign: "center",
    padding: "20px",
    borderBottom: "2px solid #c084fc",
    position: "relative",
  },
  logo: {
    width: "80px",
    height: "80px",
    borderRadius: "50%",
    border: "2px solid #c084fc",
    marginBottom: "10px",
  },
  title: {
    margin: "5px 0",
    fontSize: "2.5rem",
    color: "#c084fc",
  },
  subtitle: {
    margin: 0,
    fontSize: "1rem",
    color: "#a855f7",
  },
  authBox: {
    display: "flex",
    flexDirection: "column",
    alignItems: "center",
    marginTop: "40px",
    gap: "10px",
  },
  instructions: {
    background: "#2d0a3d",
    padding: "12px",
    borderRadius: "8px",
    fontSize: "0.9rem",
    color: "#ddd",
    marginBottom: "20px",
    maxWidth: "400px",
    textAlign: "left",
  },
  inputRow: {
    display: "flex",
    justifyContent: "center",
    gap: "10px",
    margin: "20px",
  },
  input: {
    flex: 1,
    padding: "12px",
    border: "2px solid #c084fc",
    borderRadius: "8px",
    outline: "none",
    fontSize: "1rem",
  },
  button: {
    background: "#c084fc",
    border: "none",
    borderRadius: "8px",
    padding: "12px 20px",
    cursor: "pointer",
    fontWeight: "bold",
    color: "#1a0826",
  },
  logoutButton: {
    position: "absolute",
    top: "20px",
    right: "20px",
    background: "#a855f7",
    color: "#fff",
    border: "none",
    borderRadius: "6px",
    padding: "8px 16px",
    cursor: "pointer",
  },
  resetRow: {
    display: "flex",
    justifyContent: "center",
    marginBottom: "20px",
  },
  resetButton: {
    background: "#a855f7",
    border: "none",
    borderRadius: "6px",
    padding: "10px 20px",
    cursor: "pointer",
    fontWeight: "bold",
    color: "#fff",
  },
  feed: {
    flex: 1,
    width: "90%",
    maxWidth: "700px",
    margin: "0 auto",
    display: "flex",
    flexDirection: "column",
    gap: "12px",
    overflowY: "auto",
  },
  message: {
    background: "#2d0a3d",
    padding: "12px",
    borderRadius: "8px",
    border: "1px solid #c084fc",
  },
  timestamp: {
    fontSize: "0.8rem",
    color: "#aaa",
  },
};
