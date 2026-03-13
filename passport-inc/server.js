const path = require("path");
const dotenv = require("dotenv");
dotenv.config({ path: path.join(__dirname, ".env"), debug: true });

console.log("dirname:", __dirname);
console.log("JWT_SECRET:", process.env.JWT_SECRET);

const express = require("express");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const routes = require("./src/routes");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));
app.use("/api", routes);

app.listen(PORT, () => {
  console.log(`✅ Servidor corriendo en http://localhost:${PORT}`);
});