import React, { useState, useEffect } from "react";
import { AuthContext } from "./AuthContext";

// ฟังก์ชันดึงข้อมูลจาก localStorage
const getSavedAuth = () => {
  const savedToken = localStorage.getItem("token");
  const savedUser = localStorage.getItem("user");

  try {
    if (savedToken && savedUser) {
      return {
        token: savedToken,
        user: JSON.parse(savedUser),
      };
    }
  } catch (error) {
  console.error("Invalid user data:", error);
}
  return { token: null, user: null };
};

export const AuthProvider = ({ children }) => {
  const [authData, setAuthData] = useState(() => getSavedAuth());

  useEffect(() => {
    if (authData.token && authData.user) {
      localStorage.setItem("token", authData.token);
      localStorage.setItem("user", JSON.stringify(authData.user));
    } else {
      localStorage.removeItem("token");
      localStorage.removeItem("user");
    }
  }, [authData]);

  const login = (token, user) => {
    setAuthData({ token, user });
  };

  const logout = () => {
    setAuthData({ token: null, user: null });
  };

  return (
    <AuthContext.Provider value={{ authData, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
};