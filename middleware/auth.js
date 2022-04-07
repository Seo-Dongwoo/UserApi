const jwt = require("jsonwebtoken");
const database = require("../database");

// client가 cookie를 가지고 있는지 확인하는 api
const validUser = (req, res, next) => {
  const { access_token } = req.cookies;
  if (!access_token) {
    res.status(401).send("access token이 없습니다.");
  }

  try {
    // 암호화 된 access_token을 풀어서 username에 담는다.
    const { username } = jwt.verify(access_token, "secure");

    // database에 username이 있는지 확인하는 과정
    const userInfo = database.includes((data) => data.username === username);

    if (!userInfo) {
      throw "user info가 없습니다.";
    }
    // next()가 호출이 될 때, 다음 api를 호출할 수 있다.
    next();
  } catch (error) {
    res.status(401).send("유효한 access token이 아닙니다.");
  }
};

module.exports = {
  validUser,
};
