BEGIN{
distance=100
}
{
    if($3 == "RXThresh_")
    {
        printf("%d: ", distance)
        distance += 50
        print $5
        }
}
END{

}
