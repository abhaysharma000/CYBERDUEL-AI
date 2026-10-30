import React, { createContext, useContext, useEffect, useState } from "react";
import { OperatorOption, Role, UserProfile } from "../types";
import { authApi } from "../api/client";

interface AuthContextType {
  user: UserProfile | null;
  token: string | null;
  isLoading: boolean;
  availableOperators: OperatorOption[];
  login: (username: string, password?: string) => Promise<void>;
  switchOperator: (username: string) => Promise<void>;
  logout: () => Promise<void>;
  hasPermission: (permission: string) => boolean;
  hasRole: (roles: Role[]) => boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<UserProfile | null>(null);
  const [token, setToken] = useState<string | null>(localStorage.getItem("cyberduel_auth_token"));
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [availableOperators, setAvailableOperators] = useState<OperatorOption[]>([]);

  useEffect(() => {
    // Load available demo operators
    authApi
      .getOperators()
      .then((ops) => setAvailableOperators(ops))
      .catch((err) => console.warn("Could not fetch operators:", err));

    // Verify current token or default to admin in dev
    if (token) {
      authApi
        .getMe()
        .then((profile) => {
          setUser(profile);
        })
        .catch(() => {
          localStorage.removeItem("cyberduel_auth_token");
          setToken(null);
          // Set default demo admin operator
          doDefaultLogin();
        })
        .finally(() => setIsLoading(false));
    } else {
      doDefaultLogin();
    }
  }, []);

  const doDefaultLogin = async () => {
    try {
      const res = await authApi.login("admin", "Admin@CyberDuel2026!");
      localStorage.setItem("cyberduel_auth_token", res.token);
      setToken(res.token);
      setUser(res.user);
    } catch {
      // Fallback guest viewer
      setUser({
        username: "guest_viewer",
        display_name: "Guest Operator",
        role: "viewer",
        permissions: ["read"],
      });
    } finally {
      setIsLoading(false);
    }
  };

  const login = async (username: string, password: string = "") => {
    setIsLoading(true);
    try {
      const res = await authApi.login(username, password);
      localStorage.setItem("cyberduel_auth_token", res.token);
      setToken(res.token);
      setUser(res.user);
    } finally {
      setIsLoading(false);
    }
  };

  const switchOperator = async (username: string) => {
    await login(username, "demo");
  };

  const logout = async () => {
    try {
      await authApi.logout();
    } catch (e) {
      console.warn("Logout error:", e);
    }
    localStorage.removeItem("cyberduel_auth_token");
    setToken(null);
    setUser({
      username: "guest_viewer",
      display_name: "Guest Operator",
      role: "viewer",
      permissions: ["read"],
    });
  };

  const hasPermission = (permission: string): boolean => {
    if (!user) return false;
    if (user.role === "admin" || user.permissions.includes("admin")) return true;
    return user.permissions.includes(permission);
  };

  const hasRole = (roles: Role[]): boolean => {
    if (!user) return false;
    return roles.includes(user.role);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isLoading,
        availableOperators,
        login,
        switchOperator,
        logout,
        hasPermission,
        hasRole,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
};

