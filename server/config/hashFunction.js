import bcrypt from "bcrypt"

export const hashPassword= async (password)=>{
    const salt= await bcrypt.genSaltSync(10);
    password = bcrypt.hashSync(password, salt);

    return password;
};
