import React, { useState, useEffect } from "react";
import { useForm } from "react-hook-form";
import { createUserWithEmailAndPassword } from 'firebase/auth';
import { setDoc, doc } from "firebase/firestore";
import { isEmail } from "validator";
import { auth, db } from "../../Services/FirebaseConfig.js";
import { Link } from 'react-router-dom';
import { AlertCircle, Eye, EyeOff, LockIcon } from "lucide-react";
import sodium from 'libsodium-wrappers';

import Users2Icon from '../Icons/Users2Icon.jsx';
import InputField from './InputField.jsx';
import CheckboxField from './CheckboxField.jsx';
import SubmitButton from './SubmitButton.jsx';
import SuccessMessage from './SucessMessage.jsx';

const FrontForm = () => {
  const [focusedField, setFocusedField] = useState(null);
  const [successMessage, setSuccessMessage] = useState('');
  const [isMessageVisible, setIsMessageVisible] = useState(false);
  const [showPassword, setShowPassword] = useState(false);


  const [dados, setDados] = useState(null);
  const [erro, setErro] = useState(null);
  const [chave, setChave] = useState("");

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


  const { register, handleSubmit, formState: { errors }, getValues, reset, watch } = useForm();
  const onSubmit = async (data) => {
    console.log('Dados:', dados.chave)
    setChave(dados.chave);

    try {
      const userCredential = await createUserWithEmailAndPassword(auth, data.email, data.password);
      const user = userCredential.user;

      const messageToEncrypt = "funcionario";
      const keyBase64 = 'q9egeDk+L1t2C8pgH/9rzE/ezPflr3cx6JLujZSiaX8='
      const key = sodium.from_base64(keyBase64, sodium.base64_variants.ORIGINAL);
      const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);


      const encryptedMessage = sodium.crypto_secretbox_easy(sodium.from_string(messageToEncrypt), nonce, key);
      const fullMessage = new Uint8Array([...nonce, ...encryptedMessage]);
      const encryptedMessageBase64 = sodium.to_base64(fullMessage, sodium.base64_variants.ORIGINAL);

      if (user) {
        await setDoc(doc(db, "Users", user.uid), {
          name: data.name,
          email: data.email,
          position: "Funcionario",
          tokenKey: encryptedMessageBase64.toString(),
          termsAccepted: data.privacyTerms || false
        });
        setSuccessMessage(`Bem-vindo, ${data.name}! Sua conta foi criada com sucesso.`);
        setIsMessageVisible(true);
        reset();

        setTimeout(() => {
          setIsMessageVisible(false);
          setTimeout(() => setSuccessMessage(''), 500);
        }, 5000);
      }
    } catch (error) {
      console.error("Signup error:", error);
      alert(`Erro ao criar conta: ${error.message}`);
    }
  };

  const togglePasswordVisibility = () => {
    setShowPassword(!showPassword);
  };

  const handleFocus = (field) => setFocusedField(field);
  const handleBlur = () => setFocusedField(null);
  const isFilled = (field) => !!watch(field);

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-900">
      <div className="w-full max-w-md bg-gray-800 rounded-lg shadow-md p-8">
        <div className="flex justify-center mt-1 mb-1">
          <Users2Icon />
        </div>
        <h2 className="text-3xl font-bold text-center text-white mb-8">Crie sua conta</h2>
        <p className="text-xm text-gray-300 mt-1 mb-12 text-center">
          Configure sua conta para continuar para o assistente de RH
        </p>
        {successMessage && <SuccessMessage message={successMessage} />}
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
          <InputField
            id="name"
            label="Nome"
            type="text"
            register={register}
            errors={errors.name}
            focusedField={focusedField}
            handleFocus={handleFocus}
            handleBlur={handleBlur}
            isFilled={isFilled}
            validationRules={{ required: true }}
          />
          <InputField
            id="email"
            label="Endereço de e-mail"
            type="email"
            register={register}
            errors={errors.email}
            focusedField={focusedField}
            handleFocus={handleFocus}
            handleBlur={handleBlur}
            isFilled={isFilled}
            validationRules={{ required: true, validate: isEmail }}
          />
          <InputField
            id="password"
            label="Senha"
            type="password"
            register={register}
            errors={errors.password}
            focusedField={focusedField}
            handleFocus={handleFocus}
            handleBlur={handleBlur}
            isFilled={isFilled}

            validationRules={{ required: true, minLength: 5 }}
          />

          <InputField
            id="passwordConfirmation"
            label="Confirmação da senha"
            type="password"
            register={register}
            errors={errors.passwordConfirmation}
            focusedField={focusedField}
            handleFocus={handleFocus}
            handleBlur={handleBlur}
            isFilled={isFilled}
            validationRules={{
              required: true,
              validate: (value) => value === getValues("password") || 'As senhas não coincidem.'
            }}
          />
          <CheckboxField
            id="privacyTerms"
            label={
              <>
                Concordo com os{' '}
                <Link to="/terms" className="text-blue-500 hover:underline">
                  termos de privacidade
                </Link>
              </>
            }
            register={register}
            errors={errors.privacyTerms}
          />
          <SubmitButton label="Criar Conta" />
          <Link
            to="/login"
            className="block w-full text-center py-2 px-4 mt-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-gray-600 hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500 transition-colors duration-200"
          >
            Voltar
          </Link>
        </form>
      </div>
    </div>
  );
};

export default FrontForm;
