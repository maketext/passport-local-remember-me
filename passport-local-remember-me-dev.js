/**
 * @version 0.1.1
 * @copyright Many Stallings Company 2024
 * @license MIT
 */

process.env.NODE_ENV = 'production'

const express = require('express')
const app = express()
const session = require('express-session')
const compression = require('compression')
const path = require('path')
const bodyParser = require('body-parser')
const cookieParser = require('cookie-parser')
const querystring = require('querystring')
const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const { Level } = require('level')
const _ = require('lodash')
const randomString = require("randomstring")

const dayjs = require('dayjs')
const customParseFormat = require('dayjs/plugin/customParseFormat')
const isSameOrAfter = require('dayjs/plugin/isSameOrAfter')
const { generate } = require('randomstring')

dayjs.extend(customParseFormat) // use Dayjs plugin
dayjs.extend(isSameOrAfter) // use Dayjs plugin

// Create a Key-Value database (Level.js https://leveljs.org/)
const db = new Level('many', { valueEncoding: 'json' })

const port = 8888

const ENV_GLOBAL = {
	'유저': {
		'누적': 0,
		'로그아웃누적': 0
	}
}

/**
 * @typedef {object} RememberMe - Because of not Typescript based, this naming is not worth.
 * @property {Map} map - Remember Token String Storage. Key is Token String.
 * @property {function} find - Get token related object that has contextual information (username, state, endDate) from tokenName.
 * @property {function} setState - Set token related object by tokenName.
 * @property {function} add - Add token related object by new tokenName.
 * @property {function} removeAll - Remove all data in 'map' member (Map type).
 */
const rememberMe = {
  map: new Map(),
  find: (tokenName) => {
    return this.map.get(tokenName)
  },
  setState: (tokenName, state) => {
    if(this.map.has(tokenName))
      this.map.set(tokenName, state)
  },
  add: (tokenName) => {
    this.map.set(tokenName, {})
  },
  removeAll: () => {
    this.map = new Map()
  },
  removePeriodically: () => {
    for (const [key, value] of this.map) {
      if(typeof value === 'object')
        if(value.state === '삭제됨')
          this.map.delete(key)
    }
  }
}

/**
 * Temporarilly Removed.
 * @function
 * @param {string|decimal} str - Alias for console.log. 콘솔 로그 별칭.
 */
function log(str)
{
	//console.log(str)
}

/**
 * Temporarilly Unused.
 * @function
 * @param {int} len - RandomString length. When it's value is undefined, it sets default value 32. 랜덤 문자열 길이. 그 값이 undefined일 경우 기본값 32로 설정.
 * @returns {string} 
 */
function uniqueGenerate(len) {
	try {
		if(len === undefined) len = 32
		while(true)
		{
			const token = randomString.generate({length: len, charset: 'alphabetic'})
			if(tokenMap[token] === undefined) return token
		}
	} catch(e){
	}
	return undefined
}

/**
 * Temporarilly Unused.
 * @function
 * @param {string} cmd - Command string alias for message select. 메시지 선택을 위한 명령 문자열.
 * @returns {object} {code:int, msg:string} object return. {code:int, msg:string} 오브젝트 리턴.
 */
function getMessage(cmd) {
	switch(cmd)
	{
		case '일반오류':
			return {code:1001, msg: '일반 오류가 발생하였습니다.'}
		case '없음':
			return {code:1002, msg: '데이터가 없습니다.'}
		case '읽기오류':
			return {code:1003, msg: '데이터베이스 읽기 오류가 발생하였습니다.'}
		case '쓰기오류':
			return {code:1004, msg: '데이터베이스 쓰기 오류가 발생하였습니다.'}

		case '로그인성공':
			return {code:2001, msg: '로그인에 성공하였습니다.'}
		case '로그인실패':
			return {code:2002, msg: '로그인에 실패하였습니다.'}
		case '권한없음':
			return {code:2003, msg: '접근 권한이 없습니다.'}
		case '권한있음':
			return {code:2004, msg: '접근 권한이 있습니다.'}
		
	}
	//기타
	return {code:9999, msg: '기타 에러가 발생하였습니다.'}
}

/**
 * Return whether the current session is authorized
 * 현재 세션이 인가되었는지 여부를 리턴 
 * @function
 * @param {import('express').Request} req - Express.js Request Object. Express.js 요청 객체.
 * @returns True when the current user is logged out, false when logged in. 현재 유저가 로그아웃 상태 시 true, 로그인 시 false.
 */
function hasNotUser(req) {

	const returnValue = []
	if(!_.has(req, "isUnauthenticated"))
		returnValue.push(true)
	if(typeof req.isUnauthenticated !== 'function')
		returnValue.push(true)
	else if(req.isUnauthenticated())
		returnValue.push(true)
	if(returnValue.join().includes('true'))
	{
		// 로그아웃 상태
		return true
	}
	// 로그인 상태
	return false
}

/**
 * Temporarilly Unused. Under Developement.
 * If the JavaScript expression of the ifTrue parameter value is true, issue a Remember Me token.
 * The format of the token value is 'MMS' + YYMMDD + ('20'|'1d'|'un') + randomString.
 * Draft: It is true that Semantic information remains within the Remember Me token value. So implement the logic converting to JWT tokens
 * 
 * ifTrue 파라미터 값의 자바스크립트 표현식이 true이면 리멤버 미 토큰을 발행한다. 토큰 값의 포멧은 'MMS' + YYMMDD + ('20'|'1d'|'un') + randomString 이다.
 * 초안 : 리멤버 미 토큰 값 내에 시멘틱 정보가 남아 있어 JWT 토큰으로 변환하는 로직 구현
 * @function
 * @param {boolean} ifTrue - Whether to issue a token is issued. 토큰 발행 여부.
 * @param {import('express').Request} req - Express.js Request Object. Express.js 요청 객체.
 * @param {import('express').Response} res - Express.js Response Object. Express.js 응답 객체.
 * @param {import('express').NextFunction} next - Express.js next function value. Express.js next 함수값.
 * @returns None. 없음.
 */
function makeRememberMeTokenName(ifTrue, req, res, next) {
	if(ifTrue)
	{
		console.log("// 리멤버미 토큰 발행")
		let endDate
		if(req.body.remember_me === 'un') endDate = 'un'
		else endDate = '--'

		const token = `MMS${dayjs().format('YYMMDDHHmmss')}${endDate}${randomString.generate()}`
		saveRememberMeToken(token, req.user.username)
			.then(() => {
				res.cookie('remember_me', token, { path: '/', maxAge: 8640000000 })
			})
			.finally(() => next())
		return
	}
	next()
}

/**
 * LevelDB에 존재하는 유저일 때, 새로운 리멤버미 토큰 이름을 생성하고 관련 오브젝트 {username, state, endDate} 를 초기화.
 * @function
 * @param {string} username - username string.
 * @returns Token Name String or '[유저정보없음]' at invalid username.
 */
async function addRememberMeToken(username) {
	const result = await findSomeBySome('user', username)
	let tokenName
	if(!result) tokenName = '[유저정보없음]'
	else tokenName = makeRememberMeTokenName()
	if(!rememberMe.has(tokenName)) {
		rememberMe.add(tokenName)
		rememberMe.setState(tokenName, {username: username, state: '활성', endDate: dayjs().add(7, 'd')})
	}
	return tokenName
}

/**
 * Reissue the Remember Me token according to the cookie value.
 * If the value of the remember_me cookie does not exist, or if validation has failed (junk RememberMe), or if an already authorized session is alive, then the current function is ignored.
 * 
 * 쿠키 값에 따라 리멤버 미 토큰을 재발행한다. remember_me 쿠키 값이 없거나 유효성 검증에 실패한 경우 (정크 리멤버 미) 또는 이미 인가된 세션이 살아 있는 경우는 현재 함수를 무시한다.
 * @async
 * @function
 * @param {import('express').Request} req - Express.js Request Object. Express.js 요청 객체.
 * @param {import('express').Response} res - Express.js Response Object. Express.js 응답 객체.
 * @param {import('express').NextFunction} next - Express.js next function value. Express.js next 함수값.
 * @returns 없음
 */
async function loginWithRememberMe(req, res, next) {

	// Under development
	function authRememberMeToken(token) {
		const dateNumber = _.toInteger(token.substring(3, 15))
		const endDate = token.substring(15, 25) ? token.substring(15, 25) : '' 
		////console.log(dayjs(dateNumber.toString(), 'YYMMDD').startOf('d'))
		////console.log(dayjs(new Date(2023, 0, 30)).startOf('d'))
		if(token.startsWith('MMS'))
			if(!isNaN(dateNumber))
				if(dateNumber > 200000000000 && dateNumber <= 999999999999)
					if(dayjs(dateNumber.toString(), 'YYMMDD').startOf('d').isSameOrAfter(dayjs(new Date(2023, 0, 30)).startOf('d')))
					{
						if(endDate.startsWith('un')) return dayjs(dateNumber.toString(), 'YYMMDDHHmmss').add(100, 'd').isSameOrAfter(dayjs())
					}
		return false
	}

	// Request 객체에 존재하는 리멤버미 토큰의 유효기간 만료 여부를 판단하여 유효한 토큰 상태 오브젝트를 리턴하거나 그렇지 않은 경우 null 값을 리턴.
	// Return valid token state object when token in Request object has valid End Date (compare now datetime and 'endDate' member). If not, return null.
	async function getUserStateFromRememberMeToken() {
    const state = rememberMe.find(req.body.remember_me)
		if(state.endDate.isSameOrAfter(dayjs()))
			return state
		return null
	}

	console.log("hasNotUser(req)", hasNotUser(req))
	console.log("req.isAuth=", req.isAuthenticated())
	if(!hasNotUser(req)) return next(true) // Case of session already logged in, ignore the current function.	이미 로그인 한 세션의 경우 현 함수를 무시한다.
	if(!req.body.remember_me)
	{
		//No Remember Me Cookie Value. 리멤버 미 쿠키값 없음.
		req.body.remember_me = await addRememberMeToken(req.body.username)
	}
	if(!authRememberMeToken(req.body.remember_me))
	{
		next(false) //Junk Remember Me. 정크 리멤버 미. 외부 공격 간주.
	}
	const state = await getUserStateFromRememberMeToken()
	console.log('user state', state)
	if(!_.isNil(state))
	{
		console.log("//재로그인 작업 수행")
		if(_.isNil(state.username))
		{
			// There is no useranme related remember me token. 리멤버미 토큰에 해당하는 유저이름이 없음.
			rememberMe.setState(req.body.remember_me, {state: '정크'})
			next(false)
		}
		else
			req.login({username: state.username}, function(err) {
				if (err) next(err)
				else
				{
					// Renew Remember Me Token. 리멤버미 토큰 갱신.
					rememberMe.setState(req.body.remember_me, {username: req.user.username, state: '재로그인', endDate: dayjs().add(7, 'd')})
					issueTokenWhen(req.cookies.remember_me === 'un', req, res, next)
					req.user.remember_me = req.cookies.remember_me
					app.emit('event:user_login')
					next(true)
				}
			})
	}
	else
	{
		// There is no state object of remember me token. 리멤버미 토큰의 스테이트 객체가 없음
		next(false)
	}
}



const sessionMemoryStore = new session.MemoryStore()
const secretList = ['ad6e89cc744a5fa5a23e3d9a4f07e999']
//app.set('trust proxy', 'loopback')
app.use(compression()) // Removed when using nginx because it can be controlled by reverse proxy. 역방향 프록시에서 제어가능하므로 nginx 사용시 제거.
app.use(express.static(path.join(__dirname, '..', 'res')))
app.use(cookieParser()); // Required when using passport-remember-me and corresponds to "Cannot read properties of undefined (reading 'remember_me') error. "Cannot read properties of undefined (reading 'remember_me')" 에러에 대응하며 passport-remember-me 사용시 필수.
app.use(bodyParser.urlencoded({ extended: true })) // Important when sending form! form 양식 전송시 중요!
app.use(bodyParser.json())
app.use(session({
	store: sessionMemoryStore,
  secret: secretList,
  resave: false,
  saveUninitialized: false,
  cookie: { path: '/', expires: 1000 * 60 * 15 }
}))
app.set('view engine', 'pug')
app.set('views', path.join(__dirname,'..', 'pug'))
app.use((req, res, next) => {
	//res.locals.flash = []

	log(`새 라우팅 ${req.path}`)

	res.on("finish", function() {
		log("응답메시지 전송됨.")
	})

	// Where to typing Serialization/Deserialization, components for caching verification. 직렬화/역직렬화, 캐싱확인용 컴포넌트 들어갈 자리.
	// res.append('Cache-Control', 'max-age=5') No effect. 효과 없음.
	next()
})
app.use(passport.initialize())
app.use(passport.session())

// For session store memory leak prevention periodically, iterate the session store object's keys. (Bug Fix).
// 세션 스토어 메모리 누수 방지를 위해 주기적으로 세션 스토어 객체의 키를 순회함. (버그 픽스)
setInterval(() => {
	sessionMemoryStore.all(function(err, sessionObject) {
		if(Object.keys(sessionObject).length > 0)
		{
			for (let sessionId in sessionObject) {
				sessionMemoryStore.get(sessionId, function() {} )
			}
		}
	})
}, 1000 * 60 * 15)

// Login Validation Strategy. 로그인 검증 전략.
passport.use(new LocalStrategy({
	usernameField: 'username',
	passwordField: 'password'
}, (username, password, cb) => {
	findSomeBySome('user', username)
		.then(user => {
			if(user)
				if(user.password === password)
					return cb(null, user)
			cb(null, false, { message: '유저네임이 일치하지 않습니다.' })
		})
		.catch(err => {
			console.log("로컬전략 읽기 오류")
			cb(err)
		})


	/*
	crypto.pbkdf2(password, row.salt, 310000, 32, 'sha256', function(err, hashedPassword) {
		if (err) { return cb(err); }
		if (!crypto.timingSafeEqual(row.hashed_password, hashedPassword)) {
			return cb(null, false, { message: 'Incorrect username or password.' });
		}
		;
	})*/

}));

async function findSome(some) {
	try {
		return await db.get(some)
	} catch(e) {
		return undefined
	}
}
async function findSomeBySome(some1, some2) {
	if(_.isNil(some2)) return undefined
	const some = await db.get(some1)
	return some[some2]
}
async function saveSome(key, value) {
	console.log('세이브')
	//console.log(key, value)
	return await db.put(key, value)
}
async function saveSomeBySome(key, some, value) {
	console.log('세이브')
	//console.log(key, value)
  const storage = findSome(key)
  storage[some] = value
	return await db.put(key, storage)
}
async function createIfNot(key, value) {
	try {
		await db.get(key)
		return true
	} catch(e) {
		return await db.put(key, value)
	}
}

passport.serializeUser(function(user, cb) {
  //saveSomeBySome('user', user.username, user)
	return cb(null, user.username)
})

passport.deserializeUser(function(username, cb) {
	findSomeBySome('user', username)
		.then(user => cb(null, user))
		.catch(err => cb(err))
})

app.post('/many-table/login',
	passport.authenticate('local', {
	failureFlash: getMessage('로그인실패').msg,
	failureRedirect: '/many-table/login'
}), (req, res, next) => {
	req.user.remember_me = req.body.remember_me
	//console.log(req.body)
	issueTokenWhen(req.body.remember_me === 'un', req, res, next)
}, (req, res) => {
	app.emit('event:user_login')
	res.redirect('/many-table/front')
})
app.all('/many-table/logout', async (req, res, next) => {
	await consumeRememberMeToken(req.cookies.remember_me)
	res.clearCookie('remember_me')
	req.logout(err => {
    if (err) 
			next(err)
		else
		{
			console.log("세션 로그아웃수 증가", ++ENV_GLOBAL['유저']['로그아웃누적'])
			res.send({code: 0})
			next()
		}
	})
})

app.on('event:user_login', () => {
	console.log("세션 로그인수 증가", ++ENV_GLOBAL['유저']['누적'])
})

app.listen(port, async () => {
	console.log("HTTP 네트워크 소켓 리스닝 중...")
})

app.all('/api/v2*', loginWithRememberMe, async (req, res, next) => {
	if(hasNotUser(req))
		res.status(404).send('응답이 없습니다.')
})
