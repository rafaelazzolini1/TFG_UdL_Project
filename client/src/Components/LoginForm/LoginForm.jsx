import React, { useState, useRef, useEffect } from "react";
import { AlertCircle, Eye, EyeOff, LockIcon } from "lucide-react";
import { Link, useNavigate } from 'react-router-dom';
import { signInWithEmailAndPassword } from 'firebase/auth';
import { doc, getDoc } from 'firebase/firestore';
import { auth, db } from '../../Services/FirebaseConfig';

export default function LoginForm() {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    email: "",
    password: "",
    tokenCrypt: ""
  });
  const [errors, setErrors] = useState({});
  const [loginError, setLoginError] = useState(null);
  const [showPassword, setShowPassword] = useState(false);
  const [focusedField, setFocusedField] = useState(null);

  const emailRef = useRef(null);
  const passwordRef = useRef(null);

  const validateForm = () => {
    const newErrors = {};
    if (!formData.email) {
      newErrors.email = "O endereço de e-mail é obrigatório.";
    } else if (!/^\S+@\S+$/i.test(formData.email)) {
      newErrors.email = "Por favor, insira um endereço de e-mail válido.";
    }
    if (!formData.password) {
      newErrors.password = "A senha é obrigatória.";
    }
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (emailRef.current && !emailRef.current.contains(event.target)) {
        if (formData.email === "") setFocusedField(null);
      }
      if (passwordRef.current && !passwordRef.current.contains(event.target)) {
        if (formData.password === "") setFocusedField(null);
      }
    };

    document.addEventListener("mousedown", handleClickOutside);
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
    };
  }, [formData]);

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
  };

  const generateToken = () => {
    return Math.random().toString(36).substr(2, 9) + Date.now().toString(36);
  };

  const togglePasswordVisibility = () => {
    setShowPassword(!showPassword);
  };

  const handleFocus = (field) => {
    setFocusedField(field);
  };

  const handleBlur = () => {
    setFocusedField(null);
  };



  const handleSubmit = async (e) => {
    e.preventDefault();
    if (validateForm()) {
      try {
        const userCredential = await signInWithEmailAndPassword(auth, formData.email, formData.password);
        const user = userCredential.user;

        const userDoc = await getDoc(doc(db, 'Users', user.uid));

        if (userDoc.exists()) {
          const userData = userDoc.data();
          const userPosition = userData.position;
          const tokenCrypt = userData.tokenKey;

          console.log(userPosition)

          const token = generateToken();


          sessionStorage.setItem('authToken', token);
          sessionStorage.setItem('userPosition', userPosition);

          if (userDoc.exists()) {
            if (userPosition === "Main-admin" || userPosition === "Gestor") {
              navigate('/admin-dashboard', { state: { email: formData.email, tokenCrypt: tokenCrypt } });
              // console.log(tokenCrypt);
            } else {
              navigate('/front-chat', { state: { email: formData.email, tokenCrypt: tokenCrypt } });
              // console.log(tokenCrypt);
            }
          }


        } else {
          setLoginError('Dados do usuário não encontrados. Por favor, entre em contato com o suporte.');
        }

      } catch (error) {
        console.error("Erro de login:", error);
        setLoginError('Ocorreu um erro durante o login. Por favor, tente novamente.');

      }

    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-900">
      <div className="w-full max-w-md bg-gray-800 rounded-lg shadow-md p-8">
        <div className="flex justify-center mb-6">
          <LockIcon className="h-14 w-14 text-blue-400" />
        </div>
        <h2 className="text-3xl font-bold text-center text-white mb-6">
          Entrar na sua conta
        </h2>

        <form className="space-y-6" onSubmit={handleSubmit}>
          <div className="space-y-2">
            <div className="relative">
              <div className="relative">
                <label
                  htmlFor="email"
                  className={`absolute left-3 transition-all duration-300 pointer-events-none ${focusedField === 'email' || formData.email
                    ? '-top-3 text-xs text-blue-400 bg-gray-800 px-1'
                    : 'top-2 text-sm text-gray-400'
                    }`}
                >
                  Endereço de Email
                </label>
                <input
                  id="email"
                  name="email"
                  type="email"
                  autoComplete="email"
                  required
                  className={`w-full px-3 py-2 bg-gray-700 border ${errors.email ? 'border-red-500' : 'border-gray-600'
                    } rounded-md text-white focus:outline-none focus:ring-2 focus:ring-blue-500 transition-all duration-300`}
                  placeholder=" "
                  value={formData.email}
                  onChange={handleInputChange}
                  onFocus={() => handleFocus('email')}
                  onBlur={handleBlur}
                  ref={emailRef}
                />
              </div>




            </div>
            {errors.email && (
              <p className="text-red-500 text-xs italic flex items-center mt-1">
                <AlertCircle className="h-4 w-4 mr-1" />
                {errors.email}
              </p>
            )}
          </div>
          <div className="space-y-2">
            <div className="relative">
              <div className="relative">

                <label
                  htmlFor="password"
                  className={`absolute left-3 transition-all duration-300 pointer-events-none ${focusedField === "password" || formData.password
                    ? "-top-3 text-xs text-blue-400 bg-gray-800 px-1"
                    : "top-2 text-sm text-gray-400"
                    }`}
                >
                  Senha
                </label>
                <input
                  id="password"
                  name="password"
                  type={showPassword ? "text" : "password"}
                  autoComplete="current-password"
                  required
                  className={`w-full px-3 py-2 bg-gray-700 border ${errors.password ? "border-red-500" : "border-gray-600"
                    } rounded-md text-white focus:outline-none focus:ring-2 focus:ring-blue-500 pr-10 transition-all duration-300`}
                  placeholder=" "
                  value={formData.password}
                  onChange={handleInputChange}
                  onFocus={() => handleFocus("password")}
                  onBlur={handleBlur}
                  ref={passwordRef}
                />

              </div>

              <button
                type="button"
                className="absolute inset-y-0 right-0 pr-3 flex items-center"
                onClick={togglePasswordVisibility}
              >
                {showPassword ? (
                  <EyeOff className="h-5 w-5 text-gray-400" />
                ) : (
                  <Eye className="h-5 w-5 text-gray-400" />
                )}
              </button>
            </div>
            {errors.password && (
              <p className="text-red-500 text-xs italic flex items-center mt-1">
                <AlertCircle className="h-4 w-4 mr-1" />
                {errors.password}
              </p>
            )}
          </div>


          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <input
                id="remember-me"
                name="remember-me"
                type="checkbox"
                className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
              />
              <label htmlFor="remember-me" className="ml-2 block text-sm text-gray-300">
                Lembrar-me
              </label>
            </div>
            <div className="text-sm">
              <Link to="/password-recovery" className="font-medium text-blue-400 hover:text-blue-300">
                Esqueceu sua senha?
              </Link>
            </div>
          </div>


          <div>
            <button
              type="submit"
              className="w-full py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
            >
              Entrar
            </button>
          </div>


          {loginError && (
            <p className="mt-4 text-red-500 text-center">
              {loginError}
            </p>
          )}
        </form>


        <div className="mt-6 border-t border-gray-700 pt-6">
          <p className="text-center text-sm text-gray-400">
            Não tem uma conta?{" "}
            <Link to="/signup" className="text-blue-400 hover:text-blue-300 transition-colors duration-200">
              Cadastrar
            </Link>
          </p>
        </div>


      </div>
    </div>
  );
}
