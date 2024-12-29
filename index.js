const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const sqlite3 = require("sqlite3");
const path = require("path");
const { open } = require("sqlite");
const date = require("./date");
const {
  checkUserRegistration,
  checkLoginUserData,
  checkUserTask,
  checkStatus,
} = require("./check_user_credentials");
const server_instance = express();
const dbPath = path.join(__dirname, "task_tracking_management.db");
let dataBase = null;

server_instance.use(cors());
server_instance.use(express.json());

const initialize_DataBase_and_Server = async () => {
  try {
    
    dataBase = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });
    server_instance.listen(3000, () => {
      console.log(`Server is running on http://localhost:3000:- ${date()}`);
    });
  } catch (error) {
    console.log(`Database Error: ${error.message}`);
    process.exit(1);
  }
};

initialize_DataBase_and_Server();

// Token Authorization (Middleware Function)
const authenticateToken = (request, response, next) => {
  let jwtToken;
  const authHeader = request.headers["authorization"];
  if (authHeader !== undefined) {
    jwtToken = authHeader.split(" ")[1];
    if (!jwtToken) {
      response.status(401).json("Unauthorized Access Token");
    } else {
      jwt.verify(jwtToken, "MY_SECRET_TOKEN", async (error, payload) => {
        if (error) {
          response.status(403).json("Invalid Token");
        } else {
          request.email = payload.email;
          next();
        }
      });
    }
  } else {
    response.status(401).json("Authorization header missing");
  }
};

// User Registration
server_instance.post("/user_registration", async (request, response) => {
  const { id, userName, email, password } = request.body;
  const checkUserDetail = {
    id: id,
    user_name: userName,
    email: email,
    password: password,
  };

  try {
    if (!id || !userName || !email || !password) {
      console.log(
        "User all details are mandatory to give such as 'user name', 'email', 'password' in valid format."
      );

      response
        .status(400)
        .json(
          "User all details are mandatory to give such as user name, email, password in valid format...!"
        );
    } else {
      const { error } = checkUserRegistration.validate(checkUserDetail);
      if (error) {
        console.log(`${error.details[0].message}`);
        response.status(400).json(`${error.details[0].message}`);
      } else {
        const isUserExistQuery = `SELECT * FROM user WHERE email = ?`;
        const dbUser = await dataBase.get(isUserExistQuery, [email]);
        if (!dbUser) {
          const hashPassword = await bcrypt.hash(password, 10);
          const userRegistrationQuery = `INSERT INTO user(id, user_name, email, password) VALUES (?,?,?,?);`;
          await dataBase.run(userRegistrationQuery, [
            id,
            userName,
            email,
            hashPassword,
          ]);
          response
            .status(200)
            .json(`${email} as a user ${userName} created successfully`);
          console.log(`${email} as a user ${userName} created successfully`);
        } else {
          response.status(400).json(`User ${email} is already exist`);
          console.log(`User ${email} is already exist`);
        }
      }
    }
  } catch (error) {
    response.status(500).json(`Error Message: ${error.message}`);
  }
});

// User Login
server_instance.post("/user_login", async (request, response) => {
  const { email, password } = request.body;
  const userLogInData = { email: email, password: password };
  try {
    if (!email || !password) {
      response
        .status(400)
        .json(
          "Valid email and password both are mandatory to give for user login..!"
        );
    } else {
      const { error } = checkLoginUserData.validate(userLogInData);
      if (error) {
        console.log(`${error.details[0].message}`);
        response.status(400).json(`${error.details[0].message}`);
      } else {
        const checkUserLoginQuery = `SELECT * FROM user WHERE email = ?`;
        const checkUserLogin = await dataBase.get(checkUserLoginQuery, [email]);
        if (checkUserLogin) {
          const updateLoinAtDateQuery = `UPDATE user SET login_at = ? WHERE email = ?;`;
          const updateLoinAtDate = await dataBase.run(updateLoinAtDateQuery, [
            date(),
            checkUserLogin.email,
          ]);
          const isPasswordMatch = await bcrypt.compare(
            password,
            checkUserLogin.password
          );
          if (isPasswordMatch) {
            const payload = { email: email };
            const jwtToken = jwt.sign(payload, "MY_SECRET_TOKEN");
            const tokenDetail = { jwt_token: jwtToken };
            response.status(200).json(tokenDetail);
            console.log(tokenDetail);
          } else {
            response.status(400).json("Invalid login password");
          }
        }
      }
    }
  } catch (error) {
    response.status(500).json(`Error while Login: ${error.message}`);
    console.log(`Error while Login: ${error.message}`);
  }
});

// user profile
server_instance.get(
  "/user_profile",
  authenticateToken,
  async (request, response) => {
    const { email } = request;
    try {
      const getUserDataQuery = `SELECT * FROM user WHERE email = ?;`;
      const getUserData = await dataBase.get(getUserDataQuery, [email]);

      if (getUserData) {
        response.status(200).json({
          user_detail: {
            name: getUserData.user_name,
            email: getUserData.email,
          },
        });
      } else {
        response.status(404).json({ error: "User not found" });
      }
    } catch (error) {
      console.error("Error fetching user data:", error);
      response.status(500).json(`Error-message: ${error.message}`);
    }
  }
);

// Create Task
server_instance.post(
  "/create_task",
  authenticateToken,
  async (request, response) => {
    const { email } = request;
    const { taskName, description, dueDate, status, priority } = request.body;
    try {
      const getUserDataQuery = `SELECT * FROM user WHERE email = ?;`;
      const getUserData = await dataBase.get(getUserDataQuery, [email]);
      if (!getUserData) {
        response.status(404).json("User not found..!");
      } else {
        if (!taskName || !description || !dueDate || !status || !priority) {
          response.status(400).json("All fields are mandatory to fill..!");
          console.log("All fields are mandatory to fill..!");
        } else {
          const taskData = {
            status: status,
            priority: priority,
            date: dueDate,
          };
          const { error } = checkUserTask.validate(taskData);
          if (error) {
            console.log(`${error.details[0].message}`);
            response.status(400).json(`${error.details[0].message}`);
          } else {
            const createTaskQuery = `INSERT INTO task(user_id, task_name, description, due_date, status, priority) VALUES (?,?,?,?,?,?);`;
            const createTask = await dataBase.run(createTaskQuery, [
              getUserData.id,
              taskName,
              description,
              dueDate,
              status,
              priority,
            ]);
            response
              .status(200)
              .json(`Task created successfully of ${getUserData.user_name}`);
          }
        }
      }
    } catch (error) {
      console.log(`Error-message: ${error.message}`);
      response.status(500).json(`Error-message: ${error.message}`);
    }
  }
);

// Get Task based on task_Id
server_instance.get(
  "/get_task/:taskId",
  authenticateToken,
  async (request, response) => {
    const { email } = request;
    const { taskId } = request.params;
    try {
      if (!taskId) {
        response.status(400).json("missing task id of path parameter..!");
        console.log("missing task id of path parameter..!");
      } else {
        const getTaskDataQuery =
          "SELECT task.id, task.task_name, task.description, task.due_date, task.task_created_at, task.status, task.priority FROM user INNER JOIN task ON user.id = task.user_id WHERE task.id = ? AND user.email = ?;";
        const getTaskData = await dataBase.get(getTaskDataQuery, [
          taskId,
          email,
        ]);
        if (!getTaskData) {
          response
            .status(400)
            .json(
              `Task is not found in the server of database regarding id ${taskId}`
            );
        } else {
          response.status(200).json(getTaskData);
        }
      }
    } catch (error) {
      console.log(`Error-message: ${error.message}`);
      response.status(500).json(`Error-message: ${error.message}`);
    }
  }
);

// Delete task based on ID
server_instance.delete(
  "/delete_task/:taskId",
  authenticateToken,
  async (request, response) => {
    const { email } = request; // Ensure `authenticateToken` middleware sets `email`.
    const { taskId } = request.params;

    try {
      if (!taskId) {
        console.log("Missing task ID in path parameter..!");
        return response
          .status(400)
          .json("Missing task ID in path parameter..!");
      }

      const deleteTaskQuery = `
        DELETE FROM task
        WHERE id = ? AND user_id = (
          SELECT id FROM user WHERE email = ?
        );
      `;

      const result = await dataBase.run(deleteTaskQuery, [taskId, email]);

      // SQLite3's `run` doesn't return affected rows directly.
      if (result.changes === 0) {
        console.log("No task found or unauthorized deletion attempt.");
        return response.status(404).json("Task not found or unauthorized.");
      }

      console.log("Task deleted successfully..!");
      response.status(200).json("Task deleted successfully..!");
    } catch (error) {
      console.error(`Error-message: ${error.message}`);
      response.status(500).json(`Error-message: ${error.message}`);
    }
  }
);

// Delete All Task
server_instance.delete(
  "/delete_all_task",
  authenticateToken,
  async (request, response) => {
    const { email } = request;
    try {
      const deleteAllTaskQuery = `
        DELETE FROM task
        WHERE user_id = (
          SELECT id FROM user WHERE email = ?
        );
      `;

      const result = await dataBase.run(deleteAllTaskQuery, [email]);
      console.log(result.changes);

      if (result.changes === 0) {
        console.log("No tasks found for the user.");
        return response.status(404).json("No tasks found for the user.");
      }

      console.log("All tasks deleted successfully.");
      response.status(200).json("All tasks deleted successfully.");
    } catch (error) {
      console.error(`Error-message: ${error.message}`);
      response.status(500).json(`Error-message: ${error.message}`);
    }
  }
);

// Edit Task
server_instance.put(
  "/edit_task/:taskId",
  authenticateToken,
  async (request, response) => {
    const { email } = request;
    const { taskId } = request.params;
    try {
      if (!taskId) {
        console.log("Missing task ID in path parameter..!");
        response.status(400).json("Missing task ID in path parameter..!");
      } else {
        const getTaskDataQuery = `SELECT * FROM user INNER JOIN task ON user.id = task.user_id WHERE task.id = ? AND user.email = ?;`;
        const getTaskData = await dataBase.get(getTaskDataQuery, [
          taskId,
          email,
        ]);
        console.log(getTaskData);

        if (!getTaskData) {
          response.status(404).json({ error: "Task not found" });
        } else {
          const {
            taskName = getTaskData.task_name,
            description = getTaskData.description,
            dueDate = getTaskData.due_date,
            status = getTaskData.status,
            priority = getTaskData.priority,
          } = request.body;
          const taskData = {
            status: status,
            priority: priority,
            date: dueDate,
          };
          const { error } = checkUserTask.validate(taskData);
          if (error) {
            console.log(`${error.details[0].message}`);
            response.status(400).json(`${error.details[0].message}`);
          } else {
            const editTaskQuery =
              "UPDATE task SET task_name = ?, description = ?, due_date = ?, status = ?, priority = ? WHERE id = ? AND user_id = (SELECT id FROM user WHERE email = ?);";
            const editTask = await dataBase.run(editTaskQuery, [
              taskName,
              description,
              dueDate,
              status,
              priority,
              taskId,
              email,
            ]);
            if (editTask.changes === 0) {
              response.status(404).json("Task not found or no changes made.");
            } else {
              response.status(200).json("Task updated successfully.");
            }
          }
        }
      }
    } catch (error) {
      response.status(500).json(`Error: ${error.message}`);
      console.log(`Error: ${error.message}`);
    }
  }
);

// Get List of All Task
server_instance.get(
  "/task_list",
  authenticateToken,
  async (request, response) => {
    const { email } = request;
    const { status, search } = request.query;

    try {
      if (status) {
        const taskStatus = { status };
        const { error } = checkStatus.validate(taskStatus);
        if (error) {
          console.error("Validation Error:", error.details[0].message);
          return response.status(400).json(error.details[0].message);
        }
      }

      let getTaskListQuery;
      const queryParam = [];
      queryParam.push(email);

      if (status && search) {
        getTaskListQuery = `
          SELECT id, task_name, description, due_date, task_created_at, status, priority
          FROM task
          WHERE user_id = (SELECT id FROM user WHERE email = ?)
            AND status = ?
            AND (task_name LIKE ? OR description LIKE ?);
        `;
        queryParam.push(status, `%${search}%`, `%${search}%`);
      } else if (status) {
        getTaskListQuery = `
          SELECT id, task_name, description, due_date, task_created_at, status, priority
          FROM task
          WHERE user_id = (SELECT id FROM user WHERE email = ?)
            AND status = ?;
        `;
        queryParam.push(status);
      } else if (search) {
        getTaskListQuery = `
          SELECT id, task_name, description, due_date, task_created_at, status, priority
          FROM task
          WHERE user_id = (SELECT id FROM user WHERE email = ?)
            AND (task_name LIKE ? OR description LIKE ?);
        `;
        queryParam.push(`%${search}%`, `%${search}%`);
      } else {
        getTaskListQuery = `
          SELECT id, task_name, description, due_date, task_created_at, status, priority
          FROM task
          WHERE user_id = (SELECT id FROM user WHERE email = ?);
        `;
      }

      const getAllTaskList = await dataBase.all(getTaskListQuery, queryParam);

      if (!getAllTaskList || getAllTaskList.length === 0) {
        return response.status(200).json("No tasks found.");
      }

      response.status(200).json(getAllTaskList);
    } catch (error) {
      console.error("Database query error:", error.message);
      response.status(500).json(`Server Error: ${error.message}`);
    }
  }
);
 

