
import { initializeApp } from "firebase/app";
import { getAuth } from "firebase/auth";
import { getFirestore } from "firebase/firestore";


const firebaseConfig = {
    apiKey: "AIzaSyAM2X23jX_fy5xSUpW4o6UFt4m7Xcj5IOw",
    authDomain: "tcc---rag.firebaseapp.com",
    projectId: "tcc---rag",
    storageBucket: "tcc---rag.appspot.com",
    messagingSenderId: "744812237008",
    appId: "1:744812237008:web:281a89c95d40d792dd0ed5"
  };

// Initialize Firebase
const app = initializeApp(firebaseConfig);

export const auth = getAuth(app);
export const db = getFirestore(app);
export default app;
