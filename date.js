const date = () => {
    return `${new Date().getFullYear()}-${
      new Date().getMonth() + 1
    }-${new Date().getDate()}`;
  };
  
  module.exports = date;
  