const express = require("express");
const argon2 = require("argon2");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const { validUser } = require("./middleware/auth");
const database = require("./database");

const app = express();

app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));

// test용 signup한 user들의 정보가 모두 담겨져 있다.(실제론 이런식으로 사용x)
app.get("/users", (req, res) => {
  res.send(database);
});

// client가 cookie를 가지고 있는지 확인하는 api
app.get("/secure_data", validUser, (req, res) => {
  res.send("인증된 사용자만 쓸 수 있는 API");
});

// 회원가입 api
app.post("/signup", async (req, res) => {
  const { username, password, age, birthday } = req.body;

  // password에 ehddn => aif3nsln1sngs123g 이런식의 암호화가 필수
  const hash = await argon2.hash(password);
  database.push({
    username,
    password: hash,
    age,
    birthday,
  });
  res.send("success");
});

// 로그인 api
app.post("/login", async (req, res) => {
  // username과 password가 입력으로 들어와서 api 호출
  const { username, password } = req.body;

  // 들어온 username와 일치하는 것을 database에서 찾는다.
  const user = database.filter((user) => {
    return user.username === username;
  });

  // database에 해당하는 user가 없다면 에러를 발생
  if (user.length === 0) {
    res.status(403).send("해당하는 id가 없습니다.");
  }

  // user가 있다면 password도 일치하는지 여부 체크
  // user[0].password가 받아온 password와 일치 하지 않는다면 오류 메세지 발생
  if (!(await argon2.verify(user[0].password, password))) {
    res.status(403).send("패스워드가 틀립니다.");
    return;
  }

  // 해당하는 user가 있고 password도 일치한다면 출력
  const access_token = jwt.sign({ username }, "secure");
  console.log(access_token);

  // cookie에 access_token 담기
  res.cookie("access_token", access_token, {
    // 보안상의 문제로 client에서 cookie를 열수 없게 httpOnly: true를 해준다.
    httpOnly: true,
  });
  res.send("로그인 성공!");
});

app.listen(3000, () => {
  console.log("server on!");
});
