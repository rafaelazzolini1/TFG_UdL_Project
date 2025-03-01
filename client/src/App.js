import React, { useState, useEffect } from "react";
import { BrowserRouter as Router, Route, Navigate, Routes } from 'react-router-dom';
import { useAuthState } from 'react-firebase-hooks/auth';
import { auth, db } from './Services/FirebaseConfig';
import { doc, getDoc } from 'firebase/firestore';

import LoginForm from "./Components/LoginForm/LoginForm";
import Frontform from "./Components/Form/FrontForm";
import AdminDashboard from "./AdminDashboard";
import FrontChat from "./FrontChat";

// Função de rota protegida
const ProtectedRoute = ({ children, adminRequired }) => {
  const [user, loading] = useAuthState(auth);
  const [userPosition, setUserPosition] = useState(null);
  const [dados, setDados] = useState(null);
  const [erro, setErro] = useState(null);

  useEffect(() => {
    const fetchUserPosition = async () => {
      if (user) {
        const userDoc = await getDoc(doc(db, 'Users', user.uid));
        if (userDoc.exists()) {
          setUserPosition(userDoc.data().position);
        }
      }
    };
    fetchUserPosition();
  }, [user]);

  // Função para buscar dados de criptografia
  useEffect(() => {
    const fetchDados = async () => {
      try {
        const response = await fetch('http://localhost:5000/cryptokey');
        if (!response.ok) {
          throw new Error(`Erro: ${response.status}`);
        }
        const result = await response.json();
        setDados(result);
      } catch (error) {
        setErro(error.message);
      }
    };
    fetchDados();
  }, []);

  if (loading || userPosition === null) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-gray-900">
        <div className="flex flex-col items-center space-y-4">
          <svg className="animate-spin h-10 w-10 text-blue-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
            <path className="opacity-75" fill="currentColor" d="M12 2a10 10 0 00-10 10h4a6 6 0 016-6V2z"></path>
          </svg>
          <p className="text-lg font-semibold text-blue-400">Carregando...</p>
        </div>
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/LoginForm" />;
  }

  if (adminRequired && userPosition !== 'Main-admin' && userPosition !== 'Gestor') {
    return <Navigate to="/unauthorized" />;
  }

  return children;
};

// Componente principal App
function App() {
  return (
    <Router>
      <Routes>
        <Route path="/LoginForm" element={<LoginForm />} />
        <Route path="/signup" element={<Frontform />} /> 
        <Route 
          path="/admin-dashboard" 
          element={
            <ProtectedRoute adminRequired>
              <AdminDashboard />
            </ProtectedRoute>
          } 
        />
        <Route 
          path="/front-chat" 
          element={
            <ProtectedRoute>
              <FrontChat />
            </ProtectedRoute>
          } 
        />
        <Route path="/unauthorized" element={<div>Unauthorized Access</div>} />
        <Route path="*" element={<Navigate to="/LoginForm" />} />
      </Routes>
    </Router>
  );
}

export default App;
